import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { configuration } from 'lib/configs/application.ts';
import { challenge } from 'lib/behind_proxy/api_check.ts';
import { admin } from '../provisioning/helpers.ts';
import { world, type World } from './helpers.ts';
import {
	apiCheck,
	bearer,
	changeApi,
	declareApi,
	jwtFor,
	resourcesPath,
	type ApiView
} from './api_helpers.ts';

const now = () => Math.floor(Date.now() / 1000);

/**
 * @proves An API's sign-in requirement holds at the proxy for every token presented, whenever it was issued: a token
 * whose sign-in had no code, or is older than the API allows, is answered with RFC 9470's challenge naming what is
 * missing; a token that no sign-in could fix (no sign-in time) is refused outright, never asked to sign in; a refusal
 * no new sign-in could change comes first; and turning the requirement on is previewed and applies only with the
 * numbers shown.
 */
describe("an API's sign-in requirement at the proxy", () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	/* Turns the requirement on as the console does: the preview first, then the confirmation with its counts. */
	async function requireOf(
		api: ApiView,
		body: { requireCode?: boolean; signInEveryMinutes?: number }
	) {
		const path = resourcesPath(w.acme.id, api.identifier);
		const previewed = await admin('PATCH', path, w.cookie, body);
		expect(previewed.status).toBe(409);
		const { expect: counts } = previewed.body as {
			expect: Record<string, number>;
		};
		const confirmed = await admin('PATCH', path, w.cookie, {
			...body,
			confirm: true,
			expect: counts
		});
		expect(confirmed.status).toBe(200);
	}

	async function check(api: ApiView, claims: Record<string, unknown>) {
		return apiCheck({
			slug: w.acme.slug,
			identifier: api.identifier,
			authorization: bearer(
				await jwtFor(api, {
					claims: { sub: w.acme.staffMember.accountId, ...claims }
				})
			),
			mcpMethod: 'tools/list'
		});
	}

	it('turning a requirement on answers a preview and applies only when confirmed with its counts', async () => {
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		const path = resourcesPath(w.acme.id, api.identifier);

		const previewed = await admin('PATCH', path, w.cookie, {
			requireCode: true
		});
		const stale = await admin('PATCH', path, w.cookie, {
			requireCode: true,
			confirm: true,
			expect: { withoutAuthenticator: -1, providerOnly: -1, holders: -1 }
		});
		const unchanged = await admin('GET', path, w.cookie);

		expect(previewed.status).toBe(409);
		expect(previewed.body).toMatchObject({
			confirmationRequired: true,
			changes: ['apiRequireCodeOn']
		});
		expect(
			Object.keys(
				(previewed.body as { expect: Record<string, number> }).expect
			).sort()
		).toEqual(['holders', 'providerOnly', 'withoutAuthenticator']);
		expect(stale.status).toBe(409);
		expect(unchanged.body).toMatchObject({
			requireCode: false,
			signInEveryMinutes: null
		});
	});

	it('counts the people of the group the API admits, not the whole project', async () => {
		const project = await declareApi(w.cookie, w.acme.id, {
			checkedBy: 'proxy'
		});
		const grouped = await declareApi(w.cookie, w.acme.id, {
			checkedBy: 'proxy'
		});
		await changeApi(w.cookie, w.acme.id, grouped.identifier, {
			tools: {
				rows: [],
				otherTools: 'refuse',
				withoutMethod: 'refuse',
				access: { conditions: [{ kind: 'group', groups: [w.acme.admins] }] }
			}
		});
		const countOf = async (api: ApiView) => {
			const reply = await admin(
				'PATCH',
				resourcesPath(w.acme.id, api.identifier),
				w.cookie,
				{ requireCode: true }
			);
			return (reply.body as { expect: { withoutAuthenticator: number } }).expect
				.withoutAuthenticator;
		};

		const everyone = await countOf(project);
		const admins = await countOf(grouped);

		expect(admins).toBe(1);
		expect(everyone).toBeGreaterThan(admins);
	});

	it('clearing or lengthening a requirement applies at once, and an interval outside whole hours up to 14 days is refused', async () => {
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		await requireOf(api, { requireCode: true, signInEveryMinutes: 60 });
		const path = resourcesPath(w.acme.id, api.identifier);

		const lengthened = await admin('PATCH', path, w.cookie, {
			signInEveryMinutes: 1440
		});
		const cleared = await admin('PATCH', path, w.cookie, {
			requireCode: false,
			signInEveryMinutes: null
		});
		const refused = await Promise.all(
			[0, 59, 90, 20220].map((minutes) =>
				admin('PATCH', path, w.cookie, { signInEveryMinutes: minutes })
			)
		);

		expect(lengthened.status).toBe(200);
		expect(lengthened.body).toMatchObject({ signInEveryMinutes: 1440 });
		expect(cleared.status).toBe(200);
		expect(cleared.body).toMatchObject({
			requireCode: false,
			signInEveryMinutes: null
		});
		expect(refused.map((reply) => reply.status)).toEqual([422, 422, 422, 422]);
	});

	it('a token whose sign-in had no code is asked for one, with the configured multi-factor value', async () => {
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		await requireOf(api, { requireCode: true });

		const res = await check(api, {
			auth_time: now() - 60,
			acr: configuration.acrMap.password
		});

		expect(res.status).toBe(401);
		expect(res.headers.get('x-auth-reason')).toBe('code_required');
		expect(res.headers.get('www-authenticate')).toStartWith(
			`Bearer error="insufficient_user_authentication", error_description="two-step sign-in is required", acr_values="${configuration.acrMap.multi_factor}", resource_metadata="`
		);
	});

	it('a token whose sign-in had a code is let through', async () => {
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		await requireOf(api, { requireCode: true });

		const res = await check(api, {
			auth_time: now() - 60,
			acr: configuration.acrMap.multi_factor
		});

		expect(res.status).toBe(200);
	});

	it('a token whose sign-in is older than the API allows is asked for a new one, with the age in seconds', async () => {
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		await requireOf(api, { signInEveryMinutes: 60 });

		const old = await check(api, {
			auth_time: now() - 7200,
			acr: configuration.acrMap.multi_factor
		});
		const recent = await check(api, {
			auth_time: now() - 600,
			acr: configuration.acrMap.password
		});

		expect(old.status).toBe(401);
		expect(old.headers.get('x-auth-reason')).toBe('sign_in_not_fresh');
		expect(old.headers.get('www-authenticate')).toStartWith(
			'Bearer error="insufficient_user_authentication", error_description="a more recent sign-in is required", max_age="3600", resource_metadata="'
		);
		expect(recent.status).toBe(200);
	});

	it('a token that misses both is told both', async () => {
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		await requireOf(api, { requireCode: true, signInEveryMinutes: 60 });

		const res = await check(api, {
			auth_time: now() - 7200,
			acr: configuration.acrMap.password
		});

		expect(res.status).toBe(401);
		expect(res.headers.get('x-auth-reason')).toBe('code_required');
		expect(res.headers.get('www-authenticate')).toContain(
			`acr_values="${configuration.acrMap.multi_factor}", max_age="3600"`
		);
	});

	it('a token with no sign-in behind it is refused, never asked to sign in', async () => {
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		await requireOf(api, { requireCode: true, signInEveryMinutes: 60 });

		const res = await check(api, { auth_time: undefined, acr: undefined });

		expect(res.status).toBe(403);
		expect(res.headers.get('x-auth-reason')).toBe('no_person');
		expect(res.headers.get('www-authenticate')).toBeNull();
	});

	it('a refusal no new sign-in could change comes before the request to sign in again', async () => {
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		await changeApi(w.cookie, w.acme.id, api.identifier, {
			tools: {
				rows: [],
				otherTools: 'refuse',
				withoutMethod: 'refuse',
				access: { conditions: [{ kind: 'group', groups: [w.acme.admins] }] }
			}
		});
		await requireOf(api, { requireCode: true });

		const res = await check(api, {
			sub: w.acme.staffMember.accountId,
			auth_time: now() - 60,
			acr: configuration.acrMap.password
		});

		expect(res.status).toBe(403);
		expect(res.headers.get('www-authenticate')).toBeNull();
	});

	it('no value can break the challenge or add a parameter to it', () => {
		const built = challenge('https://acme.test/metadata', {
			error: 'insufficient_scope',
			scope: 'files:read", resource_metadata="https://evil.test',
			error_description: '工具 needs a code'
		});

		expect(built).toBe(
			'Bearer error="insufficient_scope", resource_metadata="https://acme.test/metadata"'
		);
	});
});
