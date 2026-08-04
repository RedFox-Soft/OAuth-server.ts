import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import bootstrap, { agent, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { Grant } from 'lib/models/grant.js';
import { buildConsentView } from 'lib/interactions/consentView.js';
import { PAYMENT_TYPE, RESOURCE } from './consent.config.ts';

/*
 * A real cookie jar rather than a joined string: resuming an authorization request rotates the session
 * cookie, and `headers.get('set-cookie')` comma-joins values whose `expires=` attribute contains a comma
 * of its own. Same reasoning as test/rar/rar.spec.ts.
 */
type Jar = Record<string, string>;

function jarFrom(cookie: string): Jar {
	const jar: Jar = {};
	for (const pair of cookie.split('; ')) {
		const eq = pair.indexOf('=');
		if (eq > 0) jar[pair.slice(0, eq)] = pair.slice(eq + 1);
	}
	return jar;
}

function merge(jar: Jar, res: Response): Jar {
	const next = { ...jar };
	for (const raw of res.headers.getSetCookie()) {
		const [pair, ...attrs] = raw.split('; ');
		const eq = pair.indexOf('=');
		if (eq <= 0) continue;
		const name = pair.slice(0, eq);
		const value = pair.slice(eq + 1);
		const expired = attrs.some((a) =>
			a.toLowerCase().startsWith('expires=thu, 01 jan 1970')
		);
		if (expired || !value) delete next[name];
		else next[name] = value;
	}
	return next;
}

const header = (jar: Jar) =>
	Object.entries(jar)
		.map(([k, v]) => `${k}=${v}`)
		.join('; ');

/*
 * What a reader sees, with the markup taken out. The page renders a token inside a <code> element, so
 * "printed twice" is invisible to a substring search over the raw HTML — `email (<code>email</code>)`
 * contains neither "email (email)" nor anything else worth asserting on.
 */
function visible(html: string): string {
	return (
		html
			// Scripts go first, contents and all: the hydration props repeat every label and token, so a
			// count over the whole document measures the props rather than the page.
			.replace(/<script[\s\S]*?<\/script>/g, ' ')
			.replace(/<style[\s\S]*?<\/style>/g, ' ')
			.replace(/<[^>]*>/g, ' ')
			.replace(/\s+/g, ' ')
			.trim()
	);
}

/*
 * Eden types this route's `data` from the handler's `Response` return value; at runtime the client hands
 * back the rendered HTML. One narrowing here rather than a cast at every read.
 */
const bodyOf = (data: unknown): string => data as string;

// One place for the request/derived-type mismatch, so no call site repeats the cast.
const wire = (params: Record<string, string>) =>
	params as unknown as { resource: string[]; authorization_details: object[] };

const payment = {
	type: PAYMENT_TYPE,
	actions: ['initiate'],
	identifier: 'acct-1'
};

describe('consent page — every permission, stated once (US3)', () => {
	let setup: Setup;
	let jar: Jar;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'consent' });
	});

	beforeEach(async () => {
		/*
		 * Only `openid` is granted, so everything else the request asks for is outstanding. Deliberately
		 * no `resources`: seeding them here would *grant* the resource's scopes, and the resource-scope
		 * group would never appear — the prompt only reports what is missing.
		 */
		jar = jarFrom(await setup.login({ scope: 'openid' }));
	});

	async function toConsent(auth: AuthorizationRequest) {
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie: header(jar) }
		});
		expect(response.status).toBe(303);
		const location = response.headers.get('location')!;
		expect(location).toContain('/ui/');
		const [, , uid] = location.split('/');
		return { uid, jar: merge(jar, response) };
	}

	// One request that leaves all four kinds outstanding: scopes, an individual claim, a resource's
	// scopes, and a rich authorization detail.
	function fourKinds() {
		return new AuthorizationRequest({
			client_id: 'consent-app',
			scope: 'openid profile billing api:read',
			claims: { id_token: { email: null } },
			/*
			 * These two travel as query strings. AuthParams types them as the array shapes the server
			 * validates *after* parsing (checkRar normalises `authorization_details` to an array before
			 * validation), which a request literal cannot express — hence the one cast, for both.
			 */
			...wire({
				resource: RESOURCE,
				authorization_details: JSON.stringify([payment])
			})
		});
	}

	async function renderFourKinds() {
		const session = await toConsent(fourKinds());
		const { data, status } = await agent.ui({ uid: session.uid }).consent.get({
			headers: { cookie: header(session.jar) }
		});
		expect(status).toBe(200);
		const html = bodyOf(data);
		return { session, html, text: visible(html) };
	}

	it('labels every kind of permission it is asking for', async () => {
		const { text } = await renderFourKinds();

		expect(text).toContain('Your identity information');
		expect(text).toContain('Specific details about you');
		expect(text).toContain(`Access to ${RESOURCE}`);
		expect(text).toContain('Initiate a payment');
		expect(text).not.toContain('No additional permissions are requested');
	});

	it('renders a requested claim, once', async () => {
		const { text } = await renderFourKinds();

		expect(text).toContain('email');
		expect(text).not.toContain('email (email)');
	});

	it('renders a resource’s scopes under that resource, once', async () => {
		const { text } = await renderFourKinds();

		expect(text).toContain('api:read');
		expect(text).not.toContain('api:read (api:read)');
		// The indicator is named once — in the heading, not also as a bare line above it.
		expect(text.split(RESOURCE).length - 1).toBe(1);
	});

	it('renders a scope with no friendly label once, and one with a label alongside its token', async () => {
		const { text } = await renderFourKinds();

		expect(text).toContain('billing');
		expect(text).not.toContain('billing (billing)');
		// A token still earns its place when the label is prose the token does not carry.
		expect(text).toContain('Your basic profile information ( profile )');
	});

	it('keeps the four kinds in a fixed order', async () => {
		const { text } = await renderFourKinds();

		const positions = [
			text.indexOf('Your identity information'),
			text.indexOf('Specific details about you'),
			text.indexOf(`Access to ${RESOURCE}`),
			text.indexOf('Initiate a payment')
		];
		expect(positions.every((p) => p >= 0)).toBeTrue();
		expect(positions).toEqual([...positions].sort((a, b) => a - b));
	});

	it('grants exactly what the page listed', async () => {
		const { session } = await renderFourKinds();

		const { response } = await agent
			.ui({ uid: session.uid })
			.consent.post(
				{ action: 'allow' },
				{ headers: { cookie: header(session.jar) } }
			);
		expect(response.status).toBe(303);
		const location = response.headers.get('location')!;
		expect(location).toContain('https://client.example.com/cb');
		expect(location).toContain('code=');

		const grantId = [
			...(await import('../models.ts')).TestAdapter.for('Grant').store.keys()
		]
			.filter((k) => k.startsWith('Grant:'))
			.map((k) => k.slice('Grant:'.length))
			.at(-1)!;
		const grant = await Grant.find(grantId);

		const scopes = grant.getOIDCScopeEncountered().split(' ');
		expect(scopes).toContain('profile');
		expect(scopes).toContain('billing');
		expect(grant.getOIDCClaimsEncountered()).toContain('email');
		expect(grant.getResourceScopeEncountered(RESOURCE)).toContain('api:read');
		expect(grant.payload.rar).toEqual([payment]);
	});

	it('still says so when nothing is outstanding', async () => {
		const auth = new AuthorizationRequest({
			client_id: 'consent-app',
			scope: 'openid',
			prompt: 'consent'
		});
		const session = await toConsent(auth);

		const { data } = await agent.ui({ uid: session.uid }).consent.get({
			headers: { cookie: header(session.jar) }
		});

		expect(visible(bodyOf(data))).toContain(
			'No additional permissions are requested'
		);
	});
});

// The view builder is pure and reads no configuration, so its labels need no HTTP at all.
describe('buildConsentView labels (US3)', () => {
	const base = { uid: 'u', clientName: 'C' };

	it('labels an OIDC scope group', () => {
		const view = buildConsentView({
			...base,
			details: { missingOIDCScope: ['openid'] }
		});
		expect(view.permissions[0]!.label).toBe('Your identity information');
	});

	it('labels a claims group', () => {
		const view = buildConsentView({
			...base,
			details: { missingOIDCClaims: ['email'] }
		});
		expect(view.permissions[0]!.label).toBe('Specific details about you');
	});

	it('names the resource in a resource-scope group label', () => {
		const view = buildConsentView({
			...base,
			details: { missingResourceScopes: { 'urn:x': ['api:read'] } }
		});
		expect(view.permissions[0]!.label).toBe('Access to urn:x');
		// The indicator stays on the group as data, for keys and for tests.
		expect(view.permissions[0]!.resourceIndicator).toBe('urn:x');
	});

	it('keeps the operator label for a rich detail, and falls back to the raw type', () => {
		const labelled = buildConsentView({
			...base,
			details: { rar: [{ type: 'urn:t', actions: ['a'] }] },
			rarLabels: { 'urn:t': 'Do a thing' }
		});
		expect(labelled.permissions[0]!.label).toBe('Do a thing');

		const unlabelled = buildConsentView({
			...base,
			details: { rar: [{ type: 'urn:t', actions: ['a'] }] }
		});
		expect(unlabelled.permissions[0]!.label).toBe('urn:t');
	});
});
