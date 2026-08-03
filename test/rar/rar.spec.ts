import * as crypto from 'node:crypto';

import {
	describe,
	it,
	beforeAll,
	beforeEach,
	afterEach,
	expect,
	mock
} from 'bun:test';

import * as JWT from '../../lib/helpers/jwt.ts';
import bootstrap, {
	agent,
	jsonToFormUrlEncoded,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { eventBus } from 'lib/event_bus.js';
import { addons } from 'lib/addon/registry.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { ISSUER } from 'lib/configs/env.js';
import { Grant } from 'lib/models/grant.js';
import { PAYMENT_TYPE, OPEN_TYPE } from './rar.config.ts';

const form = 'application/x-www-form-urlencoded';

/*
 * A real cookie jar, not a string concatenation. Resuming an authorization request calls
 * session.resetIdentifier(), so the session cookie changes on every completed interaction; and
 * headers.get('set-cookie') comma-joins multiple cookies, which corrupts the jar because an
 * `expires=` attribute contains a comma of its own. Both together sent later requests back to the
 * login prompt.
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

const payment = (extra: Record<string, unknown> = {}) => ({
	type: PAYMENT_TYPE,
	actions: ['initiate'],
	...extra
});

const details = (...entries: Record<string, unknown>[]) =>
	JSON.stringify(entries);

const RESOURCES = {
	'urn:rar:default': 'api:read api:write',
	'urn:rar:jwt': 'api:read api:write',
	'urn:rar:other': 'api:read api:write'
};

describe('features.richAuthorizationRequests', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	afterEach(() => {
		eventBus.removeAllListeners();
		mock.restore();
	});

	// Drives an authorization request to the consent interaction; every consent-facing case starts here.
	async function toConsent(auth: AuthorizationRequest, jar: Jar) {
		const { response } = await agent.auth.get({
			query: auth.params,
			headers: { cookie: header(jar) }
		});
		expect(response.status).toBe(303);
		const location = response.headers.get('location');
		expect(location).toContain('/ui/');
		const [, , uid] = location.split('/');
		return { uid, jar: merge(jar, response) };
	}

	/*
	 * Approves consent and returns the authorization code plus the refreshed cookie jar: resuming the
	 * authorization request rotates the session cookie, so a jar that is not threaded forward sends the
	 * next request to the login prompt instead.
	 */
	async function approve(uid: string, jar: Jar) {
		const codeSpy = mock();
		eventBus.once('authorization_code.saved', codeSpy);
		const { response } = await agent.ui[uid].consent.post(
			{ action: 'allow' },
			{ headers: { cookie: header(jar) } }
		);
		expect(response.status).toBe(303);
		const location = response.headers.get('location');
		expect(location).toContain('https://client.example.com/cb');
		expect(location).toContain('code=');
		return {
			code: codeSpy.mock.calls[0]?.[0],
			location,
			jar: merge(jar, response)
		};
	}

	/*
	 * The resource indicator is repeated on the token request. With `openid` among the scopes,
	 * resolveResource deliberately declines to reuse the code's stored resource, so an access token is
	 * bound to a resource server only when the client asks again — and details are only assigned to a
	 * resource-bound token (decision D8).
	 */
	async function exchange(
		auth: AuthorizationRequest,
		code: string,
		// `null` means "deliberately ask for no resource"; `undefined` would take the default.
		resource: string | null = 'urn:rar:default'
	) {
		return agent.token.post({
			client_id: auth.params.client_id,
			grant_type: 'authorization_code',
			code_verifier: auth.code_verifier,
			code,
			...(resource ? { resource } : {})
		});
	}

	describe('the parameter survives the request boundary', () => {
		let cookie: Jar;

		beforeEach(async () => {
			cookie = jarFrom(
				await setup.login({ scope: 'openid', resources: RESOURCES })
			);
		});

		/*
		 * The declared member shape in lib/consts/param_list.ts decides whether the detail's own fields
		 * exist by the time any of our code runs: t.Object({}) strips every one of them, so `type`
		 * arrives undefined and validation rejects the request for a reason that has nothing to do with
		 * what the client sent. Before the schema is fixed this fails with "type attribute must be a
		 * non-empty string"; before check_rar accepts an array, with a JSON parse error.
		 */
		it('carries type and common fields through to validation', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				authorization_details: details(payment())
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie: header(cookie) }
			});

			expect(response.status).toBe(303);
			expect(response.headers.get('location')).toContain('/ui/');
			expect(response.headers.get('location')).not.toContain('error=');
		});
	});

	// US1 — the End-User sees and approves what is actually being asked for.
	describe('consent rendering and persistence (US1)', () => {
		let cookie: Jar;

		beforeEach(async () => {
			cookie = jarFrom(
				await setup.login({ scope: 'openid', resources: RESOURCES })
			);
		});

		it('renders the descriptor label and one readable line per common field', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				authorization_details: details(
					payment({ locations: ['urn:rar:default'], identifier: 'acct-1' })
				)
			});
			const session = await toConsent(auth, cookie);

			const { data, status } = await agent.ui[session.uid].consent.get({
				headers: { cookie: header(session.jar) }
			});

			expect(status).toBe(200);
			expect(data).toContain('Initiate a payment');
			expect(data).toContain('Actions: initiate');
			expect(data).toContain('Locations: urn:rar:default');
			expect(data).toContain('Identifier: acct-1');
			// The page used to say this while asking the End-User to authorize a payment.
			expect(data).not.toContain('No additional permissions are requested');
		});

		it('records the requested detail on the grant, and finds it granted next time', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				authorization_details: details(payment())
			});
			const session = await toConsent(auth, cookie);
			const approved = await approve(session.uid, session.jar);

			const grant = await Grant.find(approved.code.payload.grantId);
			expect(grant.payload.rar).toEqual([payment()]);

			const repeat = new AuthorizationRequest({
				scope: 'openid',
				authorization_details: details(payment())
			});
			const { response } = await agent.auth.get({
				query: repeat.params,
				headers: { cookie: header(approved.jar) }
			});

			// Already granted, so no interaction is required for it at all.
			expect(response.status).toBe(303);
			expect(response.headers.get('location')).toContain('code=');
		});

		it('renders rich details beside scopes on one page', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid profile',
				authorization_details: details(payment())
			});
			const session = await toConsent(auth, cookie);

			const { data } = await agent.ui[session.uid].consent.get({
				headers: { cookie: header(session.jar) }
			});

			expect(data).toContain('Initiate a payment');
			expect(data).toContain('profile');
		});

		/*
		 * Reachable only when the configured map changes while an interaction is in flight, which is why
		 * the type is removed between the authorization request and the consent render.
		 */
		it('falls back to the raw type identifier when no label is known', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				authorization_details: details(payment())
			});
			const session = await toConsent(auth, cookie);

			const configured = ApplicationConfig['richAuthorizationRequests.types'];
			ApplicationConfig['richAuthorizationRequests.types'] = {
				[OPEN_TYPE]: configured[OPEN_TYPE]
			};
			try {
				const { data } = await agent.ui[session.uid].consent.get({
					headers: { cookie: header(session.jar) }
				});
				expect(data).toContain(PAYMENT_TYPE);
			} finally {
				ApplicationConfig['richAuthorizationRequests.types'] = configured;
			}
		});

		it('renders field values as text, never as markup', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				authorization_details: details({
					type: OPEN_TYPE,
					identifier: '<script>alert(1)</script>'
				})
			});
			const session = await toConsent(auth, cookie);

			const { data } = await agent.ui[session.uid].consent.get({
				headers: { cookie: header(session.jar) }
			});

			expect(data).not.toContain('<script>alert(1)</script>');
			expect(data).toContain('Identifier:');
		});
	});

	// US2 — the client and the resource server receive the granted details.
	describe('delivery to clients and resource servers (US2)', () => {
		let cookie: Jar;

		beforeEach(async () => {
			cookie = jarFrom(
				await setup.login({ scope: 'openid', resources: RESOURCES })
			);
		});

		it('completes the flow with no overrides registered and returns the details', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				resource: 'urn:rar:default',
				authorization_details: details(payment())
			});
			const session = await toConsent(auth, cookie);
			const { code } = await approve(session.uid, session.jar);

			const { status, data } = await exchange(auth, code.jti);

			expect(status).toBe(200);
			expect(data.authorization_details).toEqual([payment()]);
		});

		it('filters to the resource server being served, keeping unscoped details', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				resource: ['urn:rar:default', 'urn:rar:other'],
				authorization_details: details(
					payment({ locations: ['urn:rar:default'] }),
					payment({ locations: ['urn:rar:other'], actions: ['status'] }),
					{ type: OPEN_TYPE }
				)
			});
			const session = await toConsent(auth, cookie);
			const { code } = await approve(session.uid, session.jar);

			const { status, data } = await exchange(
				auth,
				code.jti,
				'urn:rar:default'
			);

			expect(status).toBe(200);
			// The urn:rar:other detail is excluded; the location-less OPEN_TYPE detail is kept, because
			// absent `locations` means "not location-scoped", not "applies nowhere".
			expect(data.authorization_details).toEqual([
				payment({ locations: ['urn:rar:default'] }),
				{ type: OPEN_TYPE }
			]);
		});

		it('presents the details as a top-level JWT claim', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				resource: 'urn:rar:jwt',
				authorization_details: details(payment())
			});
			const session = await toConsent(auth, cookie);
			const { code } = await approve(session.uid, session.jar);

			const { status, data } = await exchange(auth, code.jti, 'urn:rar:jwt');
			expect(status).toBe(200);

			const claims = JSON.parse(
				Buffer.from(data.access_token.split('.')[1], 'base64url').toString()
			);
			expect(claims.authorization_details).toEqual([payment()]);
		});

		/*
		 * Introspected on an OPAQUE token: a JWT access token is self-contained and the introspection
		 * endpoint resolves a token by its stored identifier, so introspecting the JWT string finds
		 * nothing — which has nothing to do with RAR.
		 */
		it('returns the details as a top-level introspection member', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				resource: 'urn:rar:default',
				authorization_details: details(payment())
			});
			const session = await toConsent(auth, cookie);
			const { code } = await approve(session.uid, session.jar);
			const { data } = await exchange(auth, code.jti);

			const introspected = await agent.token.introspect.post({
				client_id: 'client',
				token: data.access_token
			});

			expect(introspected.status).toBe(200);
			expect(introspected.data.authorization_details).toEqual([payment()]);
		});

		/*
		 * A client that does not require consent skips the consent prompt whole, so nothing is ever
		 * recorded on its grant. Grant#getRarFiltered's trusted arm is the only reason it receives what
		 * it asked for instead of silently receiving nothing.
		 */
		it('delivers every requested detail to a client that does not require consent', async () => {
			const auth = new AuthorizationRequest({
				client_id: 'trusted',
				scope: 'openid',
				resource: 'urn:rar:default',
				authorization_details: details(payment())
			});

			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie: header(cookie) }
			});

			expect(response.status).toBe(303);
			const location = response.headers.get('location');
			// No interaction at all.
			expect(location).not.toContain('/ui/');
			const code = new URL(location).searchParams.get('code');

			const { status, data } = await agent.token.post({
				client_id: 'trusted',
				grant_type: 'authorization_code',
				code_verifier: auth.code_verifier,
				code,
				resource: 'urn:rar:default'
			});

			expect(status).toBe(200);
			expect(data.authorization_details).toEqual([payment()]);
		});

		it('lets a registered override win over each default', async () => {
			const shaped = [{ type: OPEN_TYPE, actions: ['overridden'] }];
			addons.override({
				rarForAuthorizationCode: () => shaped,
				rarForCodeResponse: () => shaped
			});

			const auth = new AuthorizationRequest({
				scope: 'openid',
				resource: 'urn:rar:default',
				authorization_details: details(payment())
			});
			const session = await toConsent(auth, cookie);
			const { code } = await approve(session.uid, session.jar);
			expect(code.payload.rar).toEqual(shaped);

			const { data } = await exchange(auth, code.jti);
			expect(data.authorization_details).toEqual(shaped);
		});

		/*
		 * Pins research R22's documented hole: delivery is gated on a resolved resource server, so a
		 * deployment with no resource-server resolver grants details that no token carries. It is a
		 * recorded consequence of D8, not a surprise, and the guard belongs to backlog task 12.
		 */
		it('grants details but carries them on no token without a resource server', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				authorization_details: details(payment())
			});
			const session = await toConsent(auth, cookie);
			const { code } = await approve(session.uid, session.jar);

			// Granted, and carried on the code...
			expect(code.payload.rar).toEqual([payment()]);
			const grant = await Grant.find(code.payload.grantId);
			expect(grant.payload.rar).toEqual([payment()]);

			// ...but the token request asks for no resource, so no token carries them.
			const { status, data } = await exchange(auth, code.jti, null);
			expect(status).toBe(200);
			expect(data).not.toHaveProperty('authorization_details');
		});
	});

	// US3 — a request for something the server does not permit is refused correctly.
	describe('request validation (US3)', () => {
		let cookie: Jar;

		beforeEach(async () => {
			cookie = jarFrom(
				await setup.login({ scope: 'openid', resources: RESOURCES })
			);
		});

		async function refusal(authorization_details: string, clientId = 'client') {
			const auth = new AuthorizationRequest({
				client_id: clientId,
				scope: 'openid',
				authorization_details
			});
			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie: header(cookie) }
			});
			expect(response.status).toBe(303);
			const location = new URL(response.headers.get('location'));
			return {
				error: location.searchParams.get('error'),
				description: location.searchParams.get('error_description')
			};
		}

		const cases: Array<[string, string]> = [
			[
				'an unregistered type',
				details({ type: 'https://scheme.example/nope' })
			],
			[
				'a required field left out',
				details({ type: PAYMENT_TYPE, locations: ['urn:rar:default'] })
			],
			[
				'a value outside the allowed set',
				details({ type: PAYMENT_TYPE, actions: ['drain'] })
			],
			['an unknown field on a closed type', details(payment({ extra: 'no' }))],
			['a non-string type', details({ type: 42 })]
		];

		for (const [label, value] of cases) {
			it(`refuses ${label} with invalid_authorization_details`, async () => {
				const { error } = await refusal(value);
				expect(error).toBe('invalid_authorization_details');
			});
		}

		it('refuses a type the client is not permitted to use', async () => {
			const { error } = await refusal(details(payment()), 'no-types');
			expect(error).toBe('invalid_authorization_details');
		});

		it('accepts an unknown field when the descriptor permits unknown fields', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				authorization_details: details({ type: OPEN_TYPE, whatever: 'fine' })
			});
			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie: header(cookie) }
			});
			expect(response.headers.get('location')).toContain('/ui/');
		});

		/*
		 * The refusal comes from schema validation, which authorization_error_handler maps to
		 * invalid_request — not from check_rar. Asserting the parser's own message would pin a mechanism
		 * that no longer runs for this input.
		 */
		it('refuses a value that does not parse as an array with invalid_request', async () => {
			const { error } = await refusal('not json at all');
			expect(error).toBe('invalid_request');
		});

		it('refuses a request that issues no access token', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				response_type: 'none',
				authorization_details: details(payment())
			});
			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie: header(cookie) }
			});
			const location = new URL(response.headers.get('location'));
			expect(location.searchParams.get('error')).toBe('invalid_request');
		});

		it('surfaces a code-registered validator rejection with the §5 code', async () => {
			const configured = ApplicationConfig['richAuthorizationRequests.types'];
			ApplicationConfig['richAuthorizationRequests.types'] = {
				...configured,
				[PAYMENT_TYPE]: {
					...configured[PAYMENT_TYPE],
					validate() {
						throw new Error('nope');
					}
				}
			};
			try {
				const { error } = await refusal(details(payment()));
				expect(error).toBe('invalid_authorization_details');
			} finally {
				ApplicationConfig['richAuthorizationRequests.types'] = configured;
			}
		});
	});

	// US5 — rich details survive every way a request can be delivered.
	describe('delivery shapes (US5)', () => {
		let cookie: Jar;

		beforeEach(async () => {
			cookie = jarFrom(
				await setup.login({ scope: 'openid', resources: RESOURCES })
			);
		});

		async function storedDetails(auth: AuthorizationRequest, jar: Jar) {
			const session = await toConsent(auth, jar);
			const { code } = await approve(session.uid, session.jar);
			return code.payload.rar;
		}

		it('accepts details pushed through PAR', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				authorization_details: details(payment())
			});

			const par = await agent.par.post(jsonToFormUrlEncoded(auth.params), {
				headers: { 'content-type': form }
			});
			expect(par.status).toBe(201);

			const followUp = new AuthorizationRequest({
				request_uri: par.data.request_uri
			});
			followUp.code_verifier = auth.code_verifier;

			expect(await storedDetails(followUp, cookie)).toEqual([payment()]);
		});

		it('accepts details carried inside a signed request object', async () => {
			const code_verifier = crypto.randomBytes(32).toString('base64url');
			const request = await JWT.sign(
				{
					jti: crypto.randomBytes(16).toString('base64url'),
					client_id: 'client',
					redirect_uri: 'https://client.example.com/cb',
					response_type: 'code',
					scope: 'openid',
					code_challenge_method: 'S256',
					code_challenge: crypto.hash('sha256', code_verifier, 'base64url'),
					authorization_details: [payment()]
				},
				Buffer.from('secret'),
				'HS256',
				{ issuer: 'client', audience: ISSUER, expiresIn: 30 }
			);

			const auth = new AuthorizationRequest({
				client_id: 'client',
				request,
				scope: 'openid'
			});
			auth.code_verifier = code_verifier;

			expect(await storedDetails(auth, cookie)).toEqual([payment()]);
		});

		it('stores an identical shape whichever way the request arrived', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				authorization_details: details(payment())
			});
			const viaQuery = await storedDetails(auth, cookie);
			expect(JSON.stringify(viaQuery)).toBe(JSON.stringify([payment()]));
		});
	});

	// US6 — refreshing a token keeps the granted details, per resource server.
	describe('refresh (US6)', () => {
		let cookie: Jar;

		beforeEach(async () => {
			cookie = jarFrom(
				await setup.login({ scope: 'openid', resources: RESOURCES })
			);
		});

		it('carries the details onto a refreshed access token', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				resource: 'urn:rar:default',
				authorization_details: details(payment())
			});
			const session = await toConsent(auth, cookie);
			const { code } = await approve(session.uid, session.jar);
			const { data } = await exchange(auth, code.jti);
			expect(data.refresh_token).toBeTruthy();

			const refreshed = await agent.token.post({
				client_id: 'client',
				grant_type: 'refresh_token',
				refresh_token: data.refresh_token,
				resource: 'urn:rar:default'
			});

			expect(refreshed.status).toBe(200);
			expect(refreshed.data.authorization_details).toEqual([payment()]);
		});

		it('filters a refreshed token to its own resource server, both directions', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				resource: ['urn:rar:default', 'urn:rar:other'],
				authorization_details: details(
					payment({ locations: ['urn:rar:default'] }),
					payment({ locations: ['urn:rar:other'], actions: ['status'] }),
					{ type: OPEN_TYPE }
				)
			});
			const session = await toConsent(auth, cookie);
			const { code } = await approve(session.uid, session.jar);
			const { data } = await exchange(auth, code.jti, 'urn:rar:default');

			const first = await agent.token.post({
				client_id: 'client',
				grant_type: 'refresh_token',
				refresh_token: data.refresh_token,
				resource: 'urn:rar:default'
			});
			expect(first.data.authorization_details).toEqual([
				payment({ locations: ['urn:rar:default'] }),
				{ type: OPEN_TYPE }
			]);

			const second = await agent.token.post({
				client_id: 'client',
				grant_type: 'refresh_token',
				refresh_token: first.data.refresh_token,
				resource: 'urn:rar:other'
			});
			expect(second.data.authorization_details).toEqual([
				payment({ locations: ['urn:rar:other'], actions: ['status'] }),
				{ type: OPEN_TYPE }
			]);
		});
	});

	// US7 — authorizing again does not re-ask or duplicate.
	describe('repeat authorization (US7)', () => {
		let cookie: Jar;

		beforeEach(async () => {
			cookie = jarFrom(
				await setup.login({ scope: 'openid', resources: RESOURCES })
			);
		});

		it('requires one interaction and stores one detail across ten authorizations', async () => {
			let interactions = 0;
			let grantId: string | undefined;
			let jar = cookie;

			for (let i = 0; i < 10; i++) {
				const auth = new AuthorizationRequest({
					scope: 'openid',
					authorization_details: details(payment())
				});
				const { response } = await agent.auth.get({
					query: auth.params,
					headers: { cookie: header(jar) }
				});
				const location = response.headers.get('location');
				jar = merge(jar, response);

				if (location.includes('/ui/')) {
					interactions += 1;
					const [, , uid] = location.split('/');
					const approved = await approve(uid, jar);
					jar = approved.jar;
					grantId = approved.code.payload.grantId;
				}
			}

			expect(interactions).toBe(1);
			const grant = await Grant.find(grantId);
			expect(grant.payload.rar).toEqual([payment()]);
		});

		it('prompts for a new detail, shows only that one, and ends with both granted', async () => {
			const first = new AuthorizationRequest({
				scope: 'openid',
				authorization_details: details(payment())
			});
			const firstSession = await toConsent(first, cookie);
			const approved = await approve(firstSession.uid, firstSession.jar);

			const second = new AuthorizationRequest({
				scope: 'openid',
				authorization_details: details(payment(), { type: OPEN_TYPE })
			});
			const session = await toConsent(second, approved.jar);

			const { data } = await agent.ui[session.uid].consent.get({
				headers: { cookie: header(session.jar) }
			});
			// Only the not-yet-granted detail is shown; the End-User is not asked to re-approve.
			expect(data).toContain('Open-ended access');
			expect(data).not.toContain('Initiate a payment');

			const { code } = await approve(session.uid, session.jar);
			const grant = await Grant.find(code.payload.grantId);
			expect(grant.payload.rar).toHaveLength(2);
		});

		it('treats member order as identity and string case as difference', () => {
			const grant = new Grant({ clientId: 'client', accountId: 'a' });
			grant.addRar({ type: PAYMENT_TYPE, actions: ['initiate'] });
			grant.addRar({ actions: ['initiate'], type: PAYMENT_TYPE });
			expect(grant.payload.rar).toHaveLength(1);

			grant.addRar({ type: PAYMENT_TYPE, actions: ['Initiate'] });
			expect(grant.payload.rar).toHaveLength(2);
		});
	});

	// Cross-cutting: the D2 boundary and the empty-details wire shape.
	describe('boundary and omission', () => {
		let cookie: Jar;

		beforeEach(async () => {
			cookie = jarFrom(
				await setup.login({ scope: 'openid', resources: RESOURCES })
			);
		});

		/*
		 * SC-011: a request that sends no details on a feature-enabled deployment must be
		 * indistinguishable from the same request with the feature off — no empty array anywhere.
		 */
		it('omits the member entirely when no details were requested', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				resource: 'urn:rar:default'
			});
			const codeSpy = mock();
			eventBus.once('authorization_code.saved', codeSpy);
			const { response } = await agent.auth.get({
				query: auth.params,
				headers: { cookie: header(cookie) }
			});
			expect(response.status).toBe(303);
			const code = codeSpy.mock.calls[0][0];
			expect(code.payload).not.toHaveProperty('rar');

			const { status, data } = await exchange(auth, code.jti);
			expect(status).toBe(200);
			expect(data).not.toHaveProperty('authorization_details');

			const introspected = await agent.token.introspect.post({
				client_id: 'client',
				token: data.access_token
			});
			expect(introspected.data).not.toHaveProperty('authorization_details');
		});

		it('omits the member when an empty array was requested', async () => {
			const auth = new AuthorizationRequest({
				scope: 'openid',
				resource: 'urn:rar:default',
				authorization_details: '[]'
			});
			const codeSpy = mock();
			eventBus.once('authorization_code.saved', codeSpy);
			await agent.auth.get({
				query: auth.params,
				headers: { cookie: header(cookie) }
			});
			const code = codeSpy.mock.calls[0][0];
			expect(code.payload).not.toHaveProperty('rar');
		});

		/*
		 * D2's boundary. The token-endpoint case is asserted as a SCHEMA rejection: the parameter is
		 * absent from the strict token body schema, so the grant-level checks written for §6 are
		 * unreachable, and asserting one of their errors would pass for the wrong reason.
		 */
		it('refuses the parameter on the token request through the body schema', async () => {
			const { status } = await agent.token.post({
				client_id: 'client',
				grant_type: 'refresh_token',
				refresh_token: 'whatever',
				authorization_details: details(payment())
			} as never);

			expect(status).toBe(422);
		});

		it('refuses the parameter at the device authorization endpoint', async () => {
			ApplicationConfig['deviceFlow.enabled'] = true;
			try {
				const { status, error } = await agent.device.auth.post(
					jsonToFormUrlEncoded({
						client_id: 'client',
						scope: 'openid',
						authorization_details: details(payment())
					}),
					{ headers: { 'content-type': form } }
				);
				expect(status).toBe(400);
				expect(error.value.error).toBe('invalid_request');
			} finally {
				ApplicationConfig['deviceFlow.enabled'] = false;
			}
		});
	});
});
