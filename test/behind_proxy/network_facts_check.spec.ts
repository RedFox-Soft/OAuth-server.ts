import {
	afterAll,
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { ApplicationConfig, settingsApplied } from 'lib/configs/application.js';
import { admin } from '../provisioning/helpers.ts';
import {
	behindProxyPath,
	createApp,
	world,
	type AppView,
	type World
} from './helpers.ts';
import {
	issueProxyKey,
	keyedCheck,
	proveAddresses
} from './conditions_helpers.ts';
import {
	ADDRESSES,
	clockAt,
	fullVersion,
	iso,
	loadStandard,
	pass,
	publication,
	resetNetworkFacts,
	signer,
	type Signer
} from '../network_facts/publication.ts';

const JSON_ACCEPT = 'application/json';
const NAVIGATION = 'text/html,application/xhtml+xml,*/*;q=0.8';

let w: World;
let key: string;
let foxtrust: Signer;
let undoClock: () => void = () => {};

async function appWith(facts: Record<string, unknown>): Promise<AppView> {
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
					who: { kind: 'groups', groups: [w.acme.staff] },
					conditions: [{ kind: 'network', only: [], not: [], facts }]
				}
			]
		}
	);
	expect(reply.status).toBe(200);
	return app;
}

function checkFrom(
	app: AppView,
	address: string | null,
	accept = JSON_ACCEPT,
	language?: string
) {
	return keyedCheck(
		{ slug: w.acme.slug, app },
		address === null ? null : key,
		address,
		{
			uri: '/',
			accept,
			...(language ? { headers: { 'accept-language': language } } : {})
		}
	);
}

/**
 * @proves A path with network facts in "From where" refuses an address FoxTrust's snapshot puts in a kept-out network
 * or outside the allowed countries before any sign-in, lets every other address on to the usual sign-in, and is closed
 * while the facts are off, out of date or unreadable — with a page that names neither the source nor the reason.
 */
describe('network facts at the proxy check', () => {
	let keepOut: AppView;
	let onlyDeAt: AppView;
	let notFrance: AppView;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		ApplicationConfig['networkFacts.enabled'] = true;
		w = await world();
		key = (await issueProxyKey(w.cookie, w.acme.id)).key;
		keepOut = await appWith({
			categories: ['tor', 'vpn', 'hosting'],
			outcome: { kind: 'refuse' }
		});
		onlyDeAt = await appWith({
			categories: [],
			countries: { mode: 'only', codes: ['DE', 'AT'] },
			outcome: { kind: 'refuse' }
		});
		notFrance = await appWith({
			categories: [],
			countries: { mode: 'not', codes: ['FR'] },
			outcome: { kind: 'refuse' }
		});
	});

	beforeEach(async () => {
		resetNetworkFacts();
		foxtrust = await signer('foxtrust');
		undoClock = clockAt(0.2);
		expect(await loadStandard(publication(), foxtrust)).toBe('accepted');
	});

	afterEach(() => {
		undoClock();
		ApplicationConfig['networkFacts.enabled'] = true;
	});

	afterAll(() => {
		ApplicationConfig['networkFacts.enabled'] = false;
	});

	describe('keeping Tor, VPNs and hosting out', () => {
		it('refuses a Tor exit before any sign-in', async () => {
			const response = await checkFrom(keepOut, ADDRESSES.tor);
			expect([response.status, response.headers.get('x-auth-reason')]).toEqual([
				403,
				'not_from_network'
			]);
		});

		it('refuses an address in a cloud, as hosting', async () => {
			const response = await checkFrom(keepOut, ADDRESSES.cloud);
			expect(response.headers.get('x-auth-reason')).toBe('not_from_network');
		});

		it('sends an address with no record on to sign in', async () => {
			const response = await checkFrom(keepOut, ADDRESSES.unlisted);
			expect([response.status, response.headers.get('x-auth-reason')]).toEqual([
				401,
				'no_session'
			]);
		});

		it('lets iCloud Private Relay through', async () => {
			const response = await checkFrom(keepOut, ADDRESSES.relay);
			expect(response.headers.get('x-auth-reason')).toBe('no_session');
		});

		it('shows a page that names neither the source nor the network', async () => {
			const response = await checkFrom(keepOut, ADDRESSES.tor, NAVIGATION);
			const page = await response.text();
			expect(response.status).toBe(403);
			expect(page).toContain('from where you are');
			for (const word of ['FoxTrust', 'Tor', 'VPN', 'hosting', 'Germany']) {
				expect(page).not.toContain(word);
			}
		});

		it("shows the page in the person's language", async () => {
			const response = await checkFrom(
				keepOut,
				ADDRESSES.tor,
				NAVIGATION,
				'ru'
			);
			expect(await response.text()).toContain('Отсюда нельзя открыть');
		});

		it('refuses as "From where" does when the address is not one the check believes', async () => {
			const response = await checkFrom(keepOut, null);
			expect(response.headers.get('x-auth-reason')).toBe('not_from_network');
		});
	});

	describe('allowing only some countries', () => {
		it('sends an address in an allowed country on to sign in', async () => {
			const response = await checkFrom(onlyDeAt, ADDRESSES.homeDe);
			expect(response.headers.get('x-auth-reason')).toBe('no_session');
		});

		it('refuses an address in another country', async () => {
			const response = await checkFrom(onlyDeAt, ADDRESSES.vpn);
			expect(response.headers.get('x-auth-reason')).toBe('not_from_network');
		});

		it('refuses an address with no country', async () => {
			const response = await checkFrom(onlyDeAt, ADDRESSES.unlisted);
			expect(response.headers.get('x-auth-reason')).toBe('not_from_network');
		});

		it('lets an address with no country through "not from" countries', async () => {
			const response = await checkFrom(notFrance, ADDRESSES.unlisted);
			expect(response.headers.get('x-auth-reason')).toBe('no_session');
		});
	});

	describe('when the facts cannot be vouched for', () => {
		it('closes the path once the snapshot is more than 26 hours old', async () => {
			undoClock();
			undoClock = clockAt(26.5);
			const response = await checkFrom(keepOut, ADDRESSES.unlisted, NAVIGATION);
			expect([response.status, response.headers.get('x-auth-reason')]).toEqual([
				403,
				'network_facts_unknown'
			]);
			expect(await response.text()).toContain("can't be opened right now");
		});

		it('opens the path again when a fresh snapshot loads, with nobody acting', async () => {
			undoClock();
			undoClock = clockAt(26.5);
			const published = publication();
			await published.publish({
				by: foxtrust,
				full: { version: fullVersion(1), builtAt: iso(26), entries: [] }
			});
			expect(await pass(foxtrust)).toBe('accepted');
			const response = await checkFrom(keepOut, ADDRESSES.unlisted);
			expect(response.headers.get('x-auth-reason')).toBe('no_session');
		});

		it('closes the path while the download is off', async () => {
			ApplicationConfig['networkFacts.enabled'] = false;
			settingsApplied(['networkFacts.enabled']);
			const response = await checkFrom(keepOut, ADDRESSES.unlisted);
			expect(response.headers.get('x-auth-reason')).toBe(
				'network_facts_unknown'
			);
		});

		it("closes the path for an address whose record this release can't read, and still answers", async () => {
			const published = publication();
			await published.publish({
				by: foxtrust,
				full: {
					version: fullVersion(1),
					builtAt: iso(0.1),
					entries: [{ cidr: '11.0.0.0/24', value: { categories: 'tor' } }]
				}
			});
			expect(await pass(foxtrust)).toBe('accepted');
			const response = await checkFrom(keepOut, ADDRESSES.unlisted);
			expect([response.status, response.headers.get('x-auth-reason')]).toEqual([
				403,
				'network_facts_unknown'
			]);
		});
	});
});
