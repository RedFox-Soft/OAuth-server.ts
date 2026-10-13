import { shownAccount } from '../consent_form.js';
import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import bootstrap, { agent, type Setup } from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { Grant } from 'lib/models/grant.js';
import { CONSENT_TEXTS } from 'lib/interactions/consentTexts.js';
import { visible } from '../page_text.js';
import { PAYMENT_TYPE, RESOURCE } from './consent.config.ts';
import { present } from 'test/shape.js';

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
 * Eden types this route's `data` from the handler's `Response` return value; at runtime the client hands
 * back the rendered HTML. Checked here rather than asserted at every read.
 */
function bodyOf(data: unknown): string {
	if (typeof data !== 'string') {
		throw new Error('expected the rendered consent page');
	}
	return data;
}

const payment = {
	type: PAYMENT_TYPE,
	actions: ['initiate'],
	identifier: 'acct-1'
};

/**
 * @proves The consent page names every kind of permission being asked for, once each and in a
 * fixed order, and grants exactly what it listed.
 */
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
		const response = await auth.authorize({ headers: { cookie: header(jar) } });
		expect(response.status).toBe(303);
		const location = present(
			response.headers.get('location'),
			"response.headers.get('location')"
		);
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
			resource: [RESOURCE],
			authorization_details: [payment]
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

	it('sorts what it asks into what the app will see, do, and what nobody described', async () => {
		const { text } = await renderFourKinds();

		const positions = [
			text.indexOf(CONSENT_TEXTS.groups.see),
			text.indexOf(CONSENT_TEXTS.groups.act),
			text.indexOf(CONSENT_TEXTS.groups.other)
		];
		expect(positions.every((p) => p >= 0)).toBeTrue();
		expect(positions).toEqual([...positions].sort((a, b) => a - b));
	});

	it('words a requested claim as the data it is, never as its claim name alone', async () => {
		const { text } = await renderFourKinds();

		expect(text).toContain(CONSENT_TEXTS.categories.email);
	});

	it('shows a resource scope nobody described by its technical name, under the resource', async () => {
		const { text } = await renderFourKinds();

		expect(text).toContain(CONSENT_TEXTS.resource.undescribedOwner(RESOURCE));
		expect(text).toContain('api:read');
	});

	it('shows a custom scope nobody described by its technical name, saying the administrator did not describe it', async () => {
		const { text } = await renderFourKinds();

		expect(text).toContain('billing');
		expect(text).toMatch(/administrator hasn.t described these/);
	});

	it('names a rich authorization detail by its operator label, with its fields', async () => {
		const { text } = await renderFourKinds();

		expect(text).toContain('Initiate a payment');
		expect(text).toContain(`${CONSENT_TEXTS.rarFields.actions}: initiate`);
	});

	it('grants exactly what the page listed', async () => {
		const { session } = await renderFourKinds();

		const { response } = await agent
			.ui({ uid: session.uid })
			.consent.post(
				{ action: 'allow', accountId: await shownAccount(session.uid) },
				{ headers: { cookie: header(session.jar) } }
			);
		expect(response.status).toBe(303);
		const location = present(
			response.headers.get('location'),
			"response.headers.get('location')"
		);
		expect(location).toContain('https://client.example.com/cb');
		expect(location).toContain('code=');

		const grantId = present(
			[...(await import('../models.ts')).TestAdapter.for('Grant').store.keys()]
				.filter((k) => k.startsWith('Grant:'))
				.map((k) => k.slice('Grant:'.length))
				.at(-1),
			"[ ...(await import('../models.ts')).TestAdapter.for('Grant').store.keys() ] .filter((k) => k.startsWith('Grant:')) .map((k) => k.slice('Grant:'.length)) .at(-1)"
		);
		const grant = await Grant.find(grantId);

		const scopes = grant.getOIDCScopeEncountered().split(' ');
		expect(scopes).toContain('profile');
		expect(scopes).toContain('billing');
		expect(grant.getOIDCClaimsEncountered()).toContain('email');
		expect(grant.getResourceScopeEncountered(RESOURCE)).toContain('api:read');
		expect(grant.payload.rar).toEqual([payment]);
	});

	it('says nothing new is asked when a forced consent finds everything already allowed', async () => {
		const auth = new AuthorizationRequest({
			client_id: 'consent-app',
			scope: 'openid',
			prompt: 'consent'
		});
		const session = await toConsent(auth);

		const { data } = await agent.ui({ uid: session.uid }).consent.get({
			headers: { cookie: header(session.jar) }
		});

		expect(visible(bodyOf(data))).toContain(CONSENT_TEXTS.repeat.nothingNew);
	});
});
