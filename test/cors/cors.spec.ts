import { describe, it, expect, beforeEach, afterEach } from 'bun:test';
import { hash } from 'node:crypto';

import { SignJWT, exportJWK, generateKeyPair } from 'jose';

import bootstrap, { jsonToFormUrlEncoded, type Setup } from '../test_helper.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { getProjectStore } from 'lib/adapters/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { corsRoutes } from 'lib/consts/route_classification.js';
import { ISSUER } from 'lib/configs/env.js';
import { elysia } from 'lib/index.js';
import { expectUnservedEquivalent, send } from '../feature_gate/helpers.js';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

/*
 * The CORS contract suite. Contract of record:
 * specs/011-cors-support/contracts/cors-response-contract.md.
 *
 * Every case drives the real app through `send()` (test/feature_gate/helpers.ts) rather than the Eden
 * client, because what is under test is a header set — and the flag-off cases need
 * `expectUnservedEquivalent`, which compares status, body and headers against a live request to a
 * path the server does not serve.
 *
 * Coverage, by the contract's own sections:
 *
 *   open class          — echo for any origin, Vary always, no expose-headers, no-Origin unchanged
 *   client-based class  — echo when the owning project lists the origin, over all six routes
 *   filtering           — origin absent, project empty, no project, no client, unknown token,
 *                         malformed credential; each proving the request is otherwise unaffected
 *   client id sources   — body client_id, Basic username, access token
 *   error paths         — the transform-stage 401, a 422 from validation, a 400 from a handler
 *   exposed headers     — the RFC 9449 pair on the DPoP nonce 401 and on successes
 *   negative sweep      — no CORS header on any of the 66 none-class routes, table-driven
 *   preflight           — 204 shape per route, flag-off 404 equivalence, not-a-preflight cases
 *   kill switch         — cors.enabled: false suppresses everything, and restores on re-enable
 */

export const ORIGIN = 'https://app.example.com';
export const OTHER_ORIGIN = 'https://evil.example.com';

const form = { 'content-type': 'application/x-www-form-urlencoded' };
const secret = { client_id: 'cors-client', client_secret: 'secret' };

/*
 * One request shape per client-based form endpoint. Deliberately minimal: the CORS layer runs at
 * transform, before schema validation, so a body carrying only the credentials is enough to identify
 * the client — and a request that goes on to 400 or 422 is exactly the case the header must survive.
 */
const FORM_ENDPOINTS = [
	{
		path: '/token',
		body: { ...secret, grant_type: 'client_credentials' }
	},
	{
		path: '/token/revocation',
		body: { ...secret, token: 'no-such-token' }
	},
	{
		path: '/par',
		body: {
			...secret,
			response_type: 'code',
			redirect_uri: 'https://app.example.com/cb',
			scope: 'openid'
		}
	},
	{ path: '/device/auth', body: { ...secret, scope: 'openid' } }
] as const;

function postForm(
	path: string,
	body: Record<string, unknown>,
	origin?: string
) {
	return send(path, {
		method: 'POST',
		headers: origin ? { ...form, origin } : form,
		body: jsonToFormUrlEncoded(body)
	});
}

/*
 * The in-memory project store is a process-wide singleton that bootstrap() does not clear, and
 * findByClientId returns the first project holding the id — so a project left behind by an earlier
 * case would answer for a later one and quietly invert its result. Every project this suite creates is
 * therefore tracked and destroyed after the test, rather than wiping the store (which other spec files
 * rely on for the reserved admin project).
 */
const createdProjects: string[] = [];

export async function seedProjectWithOrigins(
	clientIds: string[],
	corsOrigins: string[]
) {
	const project = await getProjectStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: 'CORS project',
		slug: `cors-${Math.random().toString(36).slice(2)}`,
		clientIds,
		corsOrigins
	});
	createdProjects.push(project._id);
	return project;
}

export async function destroySeededProjects() {
	const store = getProjectStore();
	while (createdProjects.length) {
		await store.destroy(createdProjects.pop() as string);
	}
}

describe('CORS', () => {
	let setup: Setup;

	beforeEach(async () => {
		setup = await bootstrap(import.meta.url);
	});

	afterEach(async () => {
		await destroySeededProjects();
	});

	// Guards the config itself: every later case reads a header off an endpoint that only exists
	// while its capability is on, so a broken config would present as a missing-header failure.
	it('runs against a deployment with every probed capability enabled', () => {
		expect(ApplicationConfig['par.enabled']).toBe(true);
		expect(ApplicationConfig['revocation.enabled']).toBe(true);
		expect(ApplicationConfig['deviceFlow.enabled']).toBe(true);
		expect(ApplicationConfig['userinfo.enabled']).toBe(true);
		// Asserted here rather than in the kill-switch block, which overrides it: cors.config.ts
		// deliberately does not set this key, so what bootstrap leaves behind is the shipped default.
		expect(ApplicationConfig['cors.enabled']).toBe(true);
	});

	// US1 — the two endpoints a client library must reach before it knows anything about the
	// deployment. Public to any caller already, so the origin is echoed unconditionally.
	describe('open endpoints', () => {
		const OPEN = ['/.well-known/openid-configuration', '/jwks'];

		it.each(OPEN)('echoes the requesting origin on %s', async (path) => {
			const res = await send(path, {
				method: 'GET',
				headers: { origin: ORIGIN }
			});

			expect(res.status).toBe(200);
			expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN);
			expect(res.headers.get('vary')).toBe('Origin');
		});

		it.each(OPEN)(
			'echoes an unrelated origin just as readily on %s',
			async (path) => {
				const res = await send(path, {
					method: 'GET',
					headers: { origin: OTHER_ORIGIN }
				});

				expect(res.headers.get('access-control-allow-origin')).toBe(
					OTHER_ORIGIN
				);
			}
		);

		// A browser can read the CORS-safelisted response headers here without being told to, and
		// neither endpoint ever issues a challenge — so there is nothing to expose.
		it.each(OPEN)('exposes no extra response headers on %s', async (path) => {
			const res = await send(path, {
				method: 'GET',
				headers: { origin: ORIGIN }
			});

			expect(res.headers.get('access-control-expose-headers')).toBeNull();
		});

		it.each(OPEN)(
			'never wildcards or allows credentials on %s',
			async (path) => {
				const res = await send(path, {
					method: 'GET',
					headers: { origin: ORIGIN }
				});

				expect(res.headers.get('access-control-allow-origin')).not.toBe('*');
				expect(res.headers.get('access-control-allow-credentials')).toBeNull();
			}
		);

		/*
		 * The no-Origin case matters twice over: a server-side client must be unaffected, and the
		 * response must still declare that it varies by origin — otherwise a shared cache could hand
		 * this header-less body to a browser that needed the echo.
		 */
		it.each(OPEN)(
			'leaves a request without an origin unchanged on %s',
			async (path) => {
				const withOrigin = await send(path, {
					method: 'GET',
					headers: { origin: ORIGIN }
				});
				const without = await send(path, { method: 'GET' });

				expect(without.status).toBe(withOrigin.status);
				expect(await without.text()).toBe(await withOrigin.text());
				expect(without.headers.get('access-control-allow-origin')).toBeNull();
				expect(without.headers.get('vary')).toBe('Origin');
			}
		);
	});

	// US2 — the endpoints a browser app calls directly. The origin has to be listed on the project
	// owning the calling client, so every case here turns on identifying that client.
	describe('client-based endpoints', () => {
		async function accessTokenFor(clientId: string) {
			await setup.login();
			return new AccessToken({
				accountId: setup.getAccountId(),
				grantId: setup.getGrantId(clientId),
				client: await Client.find(clientId),
				scope: 'openid'
			}).save();
		}

		describe('with the origin listed on the owning project', () => {
			beforeEach(async () => {
				await seedProjectWithOrigins(['cors-client'], [ORIGIN]);
			});

			it.each(FORM_ENDPOINTS.map((e) => [e.path, e] as const))(
				'echoes the origin on POST %s',
				async (_path, endpoint) => {
					const res = await postForm(endpoint.path, endpoint.body, ORIGIN);

					expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN);
					expect(res.headers.get('vary')).toBe('Origin');
					expect(
						res.headers.get('access-control-allow-credentials')
					).toBeNull();
				}
			);

			it('echoes the origin on a successful revocation', async () => {
				const res = await postForm(
					'/token/revocation',
					{ ...secret, token: 'no-such-token' },
					ORIGIN
				);

				expect(res.status).toBe(200);
				expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN);
			});

			it.each(['GET', 'POST'])(
				'echoes the origin on a successful %s /userinfo',
				async (method) => {
					const token = await accessTokenFor('cors-client');

					const res = await send('/userinfo', {
						method,
						headers: { origin: ORIGIN, authorization: `Bearer ${token}` }
					});

					expect(res.status).toBe(200);
					expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN);
				}
			);

			it('identifies a client that authenticates only with a Basic header', async () => {
				const basic = Buffer.from('cors-client:secret').toString('base64');

				const res = await send('/token/revocation', {
					method: 'POST',
					headers: {
						...form,
						origin: ORIGIN,
						authorization: `Basic ${basic}`
					},
					body: jsonToFormUrlEncoded({ token: 'no-such-token' })
				});

				expect(res.status).toBe(200);
				expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN);
			});

			/*
			 * The reason this layer sits at transform rather than beforeHandle. Each of these errors is
			 * raised before beforeHandle would run — the 401 from AuthPlugin's derive, the 422 from
			 * body-schema validation — and each is a response a browser app has to be able to read.
			 */
			describe('error responses', () => {
				it('carries the header on the 401 from failed client authentication', async () => {
					const res = await postForm(
						'/token',
						{
							...secret,
							client_secret: 'wrong',
							grant_type: 'client_credentials'
						},
						ORIGIN
					);

					expect(res.status).toBe(401);
					expect(await res.json()).toHaveProperty('error', 'invalid_client');
					expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN);
				});

				it('carries the header on a 400 from the token endpoint', async () => {
					const res = await postForm(
						'/token',
						{ ...secret, grant_type: 'authorization_code', code: 'nope' },
						ORIGIN
					);

					expect(res.status).toBe(400);
					expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN);
				});

				it('carries the header on a 422 from body-schema validation', async () => {
					// No grant_type: the token body schema rejects it in the validation stage, which
					// runs after transform and before beforeHandle.
					const res = await postForm('/token', { ...secret }, ORIGIN);

					expect(res.status).toBe(422);
					expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN);
				});
			});
		});

		/*
		 * The filtered cases. Every one asserts the request is *unaffected* — same status, same body —
		 * because a disallowed origin must lose the header without the server behaving differently.
		 * CORS is a response filter here, never an authorization decision (spec FR-008).
		 */
		describe('without a matching origin', () => {
			async function expectFilteredButUnaffected(origin: string) {
				const filtered = await postForm(
					'/token/revocation',
					{ ...secret, token: 'no-such-token' },
					origin
				);
				const baseline = await postForm('/token/revocation', {
					...secret,
					token: 'no-such-token'
				});

				expect(filtered.headers.get('access-control-allow-origin')).toBeNull();
				expect(filtered.status).toBe(baseline.status);
				expect(await filtered.text()).toBe(await baseline.text());
				// Still declared, so a cache cannot serve this header-less body to an allowed origin.
				expect(filtered.headers.get('vary')).toBe('Origin');
			}

			it('filters an origin absent from the list', async () => {
				await seedProjectWithOrigins(['cors-client'], [ORIGIN]);
				await expectFilteredButUnaffected(OTHER_ORIGIN);
			});

			it('filters every origin when the project lists none', async () => {
				await seedProjectWithOrigins(['cors-client'], []);
				await expectFilteredButUnaffected(ORIGIN);
			});

			it('filters when the client belongs to no project at all', async () => {
				const res = await postForm(
					'/token/revocation',
					{ client_id: 'cors-orphan', client_secret: 'secret', token: 'x' },
					ORIGIN
				);

				expect(res.status).toBe(200);
				expect(res.headers.get('access-control-allow-origin')).toBeNull();
			});

			it('filters when no client can be identified from the body', async () => {
				await seedProjectWithOrigins(['cors-client'], [ORIGIN]);

				const res = await postForm(
					'/token',
					{ grant_type: 'client_credentials' },
					ORIGIN
				);

				expect(res.headers.get('access-control-allow-origin')).toBeNull();
			});

			it('filters when the access token is unknown', async () => {
				await seedProjectWithOrigins(['cors-client'], [ORIGIN]);

				const res = await send('/userinfo', {
					method: 'GET',
					headers: { origin: ORIGIN, authorization: 'Bearer not-a-real-token' }
				});

				expect(res.status).toBe(401);
				expect(res.headers.get('access-control-allow-origin')).toBeNull();
			});

			// US4's payoff at the protocol layer: an operator's edit governs the very next request,
			// because the project is resolved per request rather than captured at boot.
			it('starts echoing as soon as an operator adds the origin', async () => {
				const project = await seedProjectWithOrigins(['cors-client'], []);
				const body = { ...secret, token: 'no-such-token' };

				const before = await postForm('/token/revocation', body, ORIGIN);
				expect(before.headers.get('access-control-allow-origin')).toBeNull();

				await getProjectStore().update(project._id, { corsOrigins: [ORIGIN] });

				const after = await postForm('/token/revocation', body, ORIGIN);
				expect(after.headers.get('access-control-allow-origin')).toBe(ORIGIN);
			});

			it('filters when the authorization header is malformed rather than erroring', async () => {
				await seedProjectWithOrigins(['cors-client'], [ORIGIN]);

				const res = await send('/userinfo', {
					method: 'GET',
					headers: { origin: ORIGIN, authorization: 'Totally-Not-A-Scheme' }
				});

				expect(res.headers.get('access-control-allow-origin')).toBeNull();
				// The malformed header is the endpoint's business to reject; the CORS layer must not
				// turn it into a different error, or a header-only concern would change the response.
				expect(res.status).toBe(401);
				expect(await res.json()).toHaveProperty(
					'error',
					'invalid_header_authorization'
				);
			});
		});

		/*
		 * The negative sweep. Driven off the classification table rather than a hand-written list, so a
		 * route added to the server without a CORS class is covered the moment it is mounted.
		 */
		describe('none-class routes for real requests', () => {
			const noneClass = elysia.routes
				.map((route) => ({ method: route.method, path: route.path }))
				.filter(
					(route) =>
						!corsRoutes.some(
							(cors) => cors.method === route.method && cors.path === route.path
						)
				);

			it('covers the whole none class', () => {
				expect(noneClass.length).toBe(elysia.routes.length - corsRoutes.length);
			});

			it.each(noneClass.map((r) => [`${r.method} ${r.path}`, r] as const))(
				'emits no CORS header on %s',
				async (_label, route) => {
					const path = route.path.replace(/:[^/]+/g, 'x').replace('*', 'x');

					for (const headers of [{ origin: ORIGIN }, undefined]) {
						const res = await send(path, { method: route.method, headers });

						for (const [name] of res.headers) {
							expect(name.startsWith('access-control-')).toBe(false);
						}
						expect(res.headers.get('vary')).toBeNull();
					}
				}
			);
		});
	});

	/*
	 * US3 — a browser cannot read a response header unless it is CORS-safelisted or explicitly exposed.
	 * RFC 9449 §7.1 and §8 therefore make these two names load-bearing: without them a browser client
	 * can see neither the challenge nor the nonce it is supposed to sign into its retry, and the DPoP
	 * flow is impossible from a browser however correctly the server behaves.
	 */
	describe('exposed response headers', () => {
		// `ath` binds the proof to the token it accompanies (RFC 9449 §4.2); without it the proof is
		// rejected as malformed before the nonce requirement is ever evaluated.
		async function dpopProof(accessToken: string, nonce?: string) {
			const keypair = await generateKeyPair('ES256', { extractable: true });
			return new SignJWT({
				htu: `${ISSUER}/userinfo`,
				htm: 'GET',
				ath: hash('sha256', accessToken, 'base64url'),
				nonce
			})
				.setProtectedHeader({
					alg: 'ES256',
					typ: 'dpop+jwt',
					jwk: await exportJWK(keypair.publicKey)
				})
				.setJti(`${Math.random()}`)
				.setIssuedAt()
				.sign(keypair.privateKey);
		}

		it('exposes both challenge headers on the DPoP nonce 401', async () => {
			await seedProjectWithOrigins(['cors-client'], [ORIGIN]);
			ApplicationConfig['dpop.requireNonce'] = true;
			const token = await new AccessToken({
				accountId: setup.getAccountId(),
				client: await Client.find('cors-client'),
				scope: 'openid'
			}).save();

			const res = await send('/userinfo', {
				method: 'GET',
				headers: {
					origin: ORIGIN,
					authorization: `DPoP ${token}`,
					dpop: await dpopProof(token)
				}
			});

			expect(res.status).toBe(401);
			expect(await res.json()).toHaveProperty('error', 'use_dpop_nonce');
			// The two headers the retry needs...
			expect(res.headers.get('dpop-nonce')).toBeString();
			expect(res.headers.get('www-authenticate')).toBeString();
			// ...and the permission for the page to actually read them.
			expect(res.headers.get('access-control-expose-headers')).toBe(
				'WWW-Authenticate, DPoP-Nonce'
			);
			expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN);
		});

		// Fixed per route class, not per response: a client cannot ask for the list conditionally, and a
		// header that appears only on failures would be unreadable exactly when it is needed.
		it('exposes them on successful client-based responses too', async () => {
			await seedProjectWithOrigins(['cors-client'], [ORIGIN]);

			const res = await postForm(
				'/token/revocation',
				{ ...secret, token: 'no-such-token' },
				ORIGIN
			);

			expect(res.status).toBe(200);
			expect(res.headers.get('access-control-expose-headers')).toBe(
				'WWW-Authenticate, DPoP-Nonce'
			);
		});

		it('exposes nothing on the open endpoints, which issue no challenge', async () => {
			for (const path of ['/.well-known/openid-configuration', '/jwks']) {
				const res = await send(path, {
					method: 'GET',
					headers: { origin: ORIGIN }
				});

				expect(res.headers.get('access-control-expose-headers')).toBeNull();
			}
		});

		it('exposes nothing when the origin is filtered', async () => {
			await seedProjectWithOrigins(['cors-client'], [ORIGIN]);

			const res = await postForm(
				'/token/revocation',
				{ ...secret, token: 'no-such-token' },
				OTHER_ORIGIN
			);

			expect(res.headers.get('access-control-expose-headers')).toBeNull();
		});
	});

	/*
	 * US6 — preflight. The security half of the feature: an OPTIONS must never reveal that an endpoint
	 * exists when its governing capability is off, because that is a one-response fingerprint of the
	 * deployment's configuration and exactly what the feature gate goes out of its way to hide.
	 */
	describe('preflight', () => {
		function preflight(
			path: string,
			method: string,
			extra: Record<string, string> = {}
		) {
			return send(path, {
				method: 'OPTIONS',
				headers: {
					origin: ORIGIN,
					'access-control-request-method': method,
					...extra
				}
			});
		}

		const CORS_ENABLED = [
			['GET', '/.well-known/openid-configuration', 'GET'],
			['GET', '/jwks', 'GET'],
			['POST', '/token', 'POST'],
			['GET', '/userinfo', 'GET, POST'],
			['POST', '/userinfo', 'GET, POST'],
			['POST', '/token/revocation', 'POST'],
			['POST', '/par', 'POST'],
			['POST', '/device/auth', 'POST']
		] as const;

		it.each(
			CORS_ENABLED.map(([m, p, allow]) => [`${m} ${p}`, p, m, allow] as const)
		)('answers a preflight for %s', async (_label, path, method, allowed) => {
			const res = await preflight(path, method, {
				'access-control-request-headers': 'authorization, dpop'
			});

			expect(res.status).toBe(204);
			expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN);
			// Derived from the classification table, so a path serving two methods advertises both.
			expect(res.headers.get('access-control-allow-methods')).toBe(allowed);
			expect(res.headers.get('access-control-allow-headers')).toBe(
				'authorization, dpop'
			);
			expect(res.headers.get('access-control-max-age')).toBe('3600');
			expect(res.headers.get('vary')).toBe('Origin');
		});

		// Compared against a live unrouted probe rather than a literal: the not-found body is slated to
		// change (backlog task 14) and this equality must survive that.
		it('carries the same no-store headers a 404 carries', async () => {
			const flight = await preflight('/token', 'POST');
			const unserved = await send('/_not_a_mounted_route', {
				method: 'OPTIONS'
			});

			expect(flight.headers.get('cache-control')).toBe(
				unserved.headers.get('cache-control')
			);
			expect(flight.headers.get('surrogate-control')).toBe(
				unserved.headers.get('surrogate-control')
			);
		});

		it('omits allow-headers when the preflight asked about none', async () => {
			const res = await preflight('/token', 'POST');

			expect(res.status).toBe(204);
			expect(res.headers.get('access-control-allow-headers')).toBeNull();
		});

		it('carries no body', async () => {
			const res = await preflight('/jwks', 'GET');

			expect(await res.text()).toBe('');
		});

		/*
		 * The no-leak requirement. `gatedFlagForRequest` matches exactly on (method, path), so the
		 * requested method has to be substituted for OPTIONS — get that wrong and a preflight answers
		 * 204 on an endpoint that 404s every real request.
		 */
		describe('when the governing capability is off', () => {
			it.each([
				['par.enabled', '/par', 'POST'],
				['revocation.enabled', '/token/revocation', 'POST'],
				['deviceFlow.enabled', '/device/auth', 'POST'],
				['userinfo.enabled', '/userinfo', 'GET']
			] as const)(
				'is indistinguishable from an unrouted path with %s off',
				async (flag, path, method) => {
					ApplicationConfig[flag] = false;

					await expectUnservedEquivalent(path, {
						method: 'OPTIONS',
						headers: {
							origin: ORIGIN,
							'access-control-request-method': method
						}
					});
				}
			);

			// The real request 404s too, so the pair cannot be told apart by trying both.
			it('matches the real request it guards', async () => {
				ApplicationConfig['par.enabled'] = false;

				await expectUnservedEquivalent('/par', {
					method: 'OPTIONS',
					headers: { origin: ORIGIN, 'access-control-request-method': 'POST' }
				});
				await expectUnservedEquivalent('/par', {
					method: 'POST',
					headers: { ...form, origin: ORIGIN },
					body: jsonToFormUrlEncoded(secret)
				});
			});
		});

		it.each([
			'/auth',
			'/ui/x/login',
			'/admin/api/projects',
			'/token/introspect'
		])('falls through to 404 on the none-class route %s', async (path) => {
			const res = await preflight(path, 'POST');

			expect(res.status).toBe(404);
			for (const [name] of res.headers) {
				expect(name.startsWith('access-control-')).toBe(false);
			}
		});

		it('is not a preflight without Access-Control-Request-Method', async () => {
			const res = await send('/token', {
				method: 'OPTIONS',
				headers: { origin: ORIGIN }
			});

			expect(res.status).toBe(404);
			expect(res.headers.get('access-control-allow-origin')).toBeNull();
		});

		it('is not a preflight without an Origin', async () => {
			const res = await send('/token', {
				method: 'OPTIONS',
				headers: { 'access-control-request-method': 'POST' }
			});

			expect(res.status).toBe(404);
		});

		// A preflight carries no credentials and no body, so no per-client decision is possible: the
		// client-based restriction applies to the real request only.
		it('answers a client-based route for an origin no project lists', async () => {
			const res = await preflight('/token', 'POST');

			expect(res.status).toBe(204);
			expect(res.headers.get('access-control-allow-origin')).toBe(ORIGIN);
		});
	});

	/*
	 * US5 — the kill switch. Not the primary means of closure (a project with no origins already grants
	 * nothing, which is why the default is on) but the lever an operator reaches for during an incident.
	 */
	describe('cors.enabled: false', () => {
		beforeEach(async () => {
			await seedProjectWithOrigins(['cors-client'], [ORIGIN]);
			ApplicationConfig['cors.enabled'] = false;
		});

		it('emits nothing on the open endpoints, not even Vary', async () => {
			for (const path of ['/.well-known/openid-configuration', '/jwks']) {
				const res = await send(path, {
					method: 'GET',
					headers: { origin: ORIGIN }
				});

				expect(res.status).toBe(200);
				expect(res.headers.get('access-control-allow-origin')).toBeNull();
				expect(res.headers.get('vary')).toBeNull();
			}
		});

		it('emits nothing on a client-based endpoint whose origin is allowed', async () => {
			const res = await postForm(
				'/token/revocation',
				{ ...secret, token: 'no-such-token' },
				ORIGIN
			);

			expect(res.status).toBe(200);
			expect(res.headers.get('access-control-allow-origin')).toBeNull();
			expect(res.headers.get('access-control-expose-headers')).toBeNull();
			expect(res.headers.get('vary')).toBeNull();
		});

		it('makes preflight indistinguishable from an unrouted path', async () => {
			await expectUnservedEquivalent('/token', {
				method: 'OPTIONS',
				headers: { origin: ORIGIN, 'access-control-request-method': 'POST' }
			});
		});

		// Read flat off ApplicationConfig per request rather than captured at boot, so the switch is a
		// live lever within one long-lived instance — which is also what lets this suite flip it per case.
		it('restores every behaviour when switched back on', async () => {
			const off = await send('/jwks', {
				method: 'GET',
				headers: { origin: ORIGIN }
			});
			expect(off.headers.get('access-control-allow-origin')).toBeNull();

			ApplicationConfig['cors.enabled'] = true;

			const on = await send('/jwks', {
				method: 'GET',
				headers: { origin: ORIGIN }
			});
			expect(on.headers.get('access-control-allow-origin')).toBe(ORIGIN);

			const flight = await send('/token', {
				method: 'OPTIONS',
				headers: { origin: ORIGIN, 'access-control-request-method': 'POST' }
			});
			expect(flight.status).toBe(204);
		});
	});
});
