import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { eventBus } from 'lib/event_bus.ts';
import { checkCallerOf } from 'lib/behind_proxy/rate_limit.ts';
import { whenUsageRecorded } from 'lib/behind_proxy/usage.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	behindProxyPath,
	checkApp,
	createApp,
	world,
	type AppView,
	type World
} from './helpers.ts';
import {
	issueProxyKey,
	KEY_HEADER,
	keyedCheck,
	PROBE_ADDRESS,
	proveAddresses
} from './conditions_helpers.ts';

let w: World;
let key: string;

async function appWith(condition: Record<string, unknown>): Promise<AppView> {
	const app = await createApp(w.cookie, w.acme.id, {
		rootGroups: [w.acme.staff]
	});
	await proveAddresses({ slug: w.acme.slug, app }, key);
	const reply = await admin(
		'PATCH',
		behindProxyPath(w.acme.id, app.id),
		w.cookie,
		{
			rules: [
				{
					path: '/',
					who: { kind: 'project' },
					conditions: [{ kind: 'network', ...condition }]
				}
			]
		}
	);
	expect(reply.status).toBe(200);
	return app;
}

/* A check carrying exactly the given header lines, as a proxy that passed a browser's own headers would. */
function rawCheck(app: AppView, lines: [string, string][]): Promise<Response> {
	const headers = new Headers();
	for (const [name, value] of lines) headers.append(name, value);
	/* Two lines of one header arrive joined by a comma, exactly as a proxy forwards them. */
	return checkApp(
		{ slug: w.acme.slug, app },
		{
			uri: '/',
			accept: 'application/json',
			headers: Object.fromEntries(headers.entries())
		}
	);
}

/**
 * @proves No address a browser could choose decides a network condition: only one strict, public address written by a
 * proxy that shows the project's key is believed, and the address is compared and nothing else.
 */
describe('the person’s address at the check', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		key = (await issueProxyKey(w.cookie, w.acme.id)).key;
	});

	describe('with Not from 192.0.2.0/24', () => {
		it.each([
			['no key', [['X-Forwarded-For', '198.51.100.9']]],
			[
				'a wrong key',
				[
					[KEY_HEADER, 'fpk_wrong'],
					['X-Forwarded-For', '198.51.100.9']
				]
			],
			['two addresses in one header', 'key:1.2.3.4, 198.51.100.9'],
			['two headers', 'key2:198.51.100.9'],
			['a port', 'key:198.51.100.9:80'],
			['brackets', 'key:[2001:db8::1]'],
			['a zone', 'key:fe80::1%eth0'],
			['a leading zero', 'key:010.0.0.1'],
			['a short form', 'key:1.2.3'],
			['an integer', 'key:16909060'],
			['a private address', 'key:10.0.0.1'],
			['a shared (CGNAT) address', 'key:100.64.0.1']
		] as const)('%s is refused', async (_case, spec) => {
			const app = await appWith({ only: [], not: ['192.0.2.0/24'] });
			const lines: [string, string][] =
				typeof spec === 'string'
					? spec.startsWith('key2:')
						? [
								[KEY_HEADER, key],
								['X-Forwarded-For', spec.slice(5)],
								['X-Forwarded-For', spec.slice(5)]
							]
						: [
								[KEY_HEADER, key],
								['X-Forwarded-For', spec.slice(4)]
							]
					: spec.map(([n, v]) => [n, v] as [string, string]);

			const response = await rawCheck(app, lines);

			expect(response.status).toBe(403);
			expect(response.headers.get('x-auth-reason')).toBe('not_from_network');
		});
	});

	describe('with Only from 203.0.113.0/24', () => {
		it.each([
			['no key', null, '203.0.113.9'],
			['a wrong key', 'fpk_wrong', '203.0.113.9'],
			['two addresses', 'key', '203.0.113.9, 203.0.113.10'],
			['a port', 'key', '203.0.113.9:80'],
			['leading zeros', 'key', '203.000.113.9'],
			['an integer', 'key', '3405803785']
		] as const)('%s never passes', async (_case, presented, address) => {
			const app = await appWith({ only: ['203.0.113.0/24'], not: [] });

			const response = await keyedCheck(
				{ slug: w.acme.slug, app },
				presented === 'key' ? key : presented,
				address,
				{ accept: 'application/json' }
			);

			expect(response.headers.get('x-auth-reason')).toBe('not_from_network');
		});
	});

	it('is in no decision event, and the check’s own caller is not the person', async () => {
		const app = await appWith({ only: ['203.0.113.0/24'], not: [] });
		const seen: unknown[] = [];
		const listener = (event: unknown) => seen.push(event);
		eventBus.on('behind_proxy.decision', listener);
		const request = new Request('http://localhost/verify', {
			headers: { 'X-Forwarded-For': '203.0.113.77', [KEY_HEADER]: key }
		});

		await keyedCheck({ slug: w.acme.slug, app }, key, '203.0.113.77', {
			accept: 'application/json'
		});
		eventBus.off('behind_proxy.decision', listener);

		expect(seen.length).toBeGreaterThan(0);
		expect(JSON.stringify(seen)).not.toContain('203.0.113.77');
		expect(checkCallerOf(request)).not.toBe('203.0.113.77');
	});

	it('a network condition cannot be saved again after the probe address reached the check', async () => {
		const app = await appWith({ only: ['203.0.113.0/24'], not: [] });

		await keyedCheck({ slug: w.acme.slug, app }, key, PROBE_ADDRESS, {
			accept: 'application/json'
		});
		await whenUsageRecorded();
		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			{
				rules: [
					{
						path: '/',
						who: { kind: 'project' },
						conditions: [
							{ kind: 'network', only: ['198.51.100.0/24'], not: [] }
						]
					}
				]
			}
		);

		expect(reply.status).toBe(409);
		expect((reply.body as { code: string }).code).toBe(
			'proxy_address_unproven'
		);
	});

	describe('the self-test page', () => {
		it('shows the address the check believed, not one a browser wrote', async () => {
			const app = await createApp(w.cookie, w.acme.id, {
				rootGroups: [w.acme.staff]
			});

			const answered = await keyedCheck(
				{ slug: w.acme.slug, app },
				key,
				'203.0.113.9',
				{
					uri: '/_foxauth/address'
				}
			);
			const page = await answered.text();
			const keyless = await (
				await keyedCheck({ slug: w.acme.slug, app }, null, '203.0.113.9', {
					uri: '/_foxauth/address'
				})
			).text();

			/* Not a success: a proxy passes any 2xx of its check on to the app, and the page would never be shown. */
			expect(answered.status).toBe(403);
			expect(page).toContain('203.0.113.9');
			expect(keyless).not.toContain('203.0.113.9');
			expect(keyless).toContain('did not show its proxy key');
		});
	});
});
