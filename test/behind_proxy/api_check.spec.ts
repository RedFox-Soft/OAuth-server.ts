import { afterEach, beforeAll, describe, expect, it, spyOn } from 'bun:test';

import bootstrap from '../test_helper.js';
import { getProtectedResourceStore } from 'lib/adapters/index.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { setPeerResolverForTests } from 'lib/helpers/caller_address.ts';
import { resetUnauthenticatedCharge } from 'lib/helpers/unauthenticated_charge.ts';
import {
	resetCheckRateLimiter,
	setCheckRateBoundsForTests
} from 'lib/behind_proxy/rate_limit.ts';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import {
	answerOf,
	project,
	scheduleDeletion,
	world,
	type World
} from './helpers.ts';
import {
	apiCheck,
	apiCheckUrl,
	bearer,
	declareApi,
	freshIdentifier,
	jwtFor,
	opaqueFor,
	type ApiCheck,
	type Minted
} from './api_helpers.ts';
import { elysia } from 'lib/index.ts';

/* Set up once, on first use, so a case that needs it fails with the reason the setup failed. */
function once<T>(make: () => Promise<T>): () => Promise<T> {
	let made: Promise<T> | undefined;
	return () => (made ??= make());
}

/**
 * @proves The check a proxy makes for an API answers only about the API it names, at that API's host: a token is
 * read only from the one header that carries it, every way of naming an API the project does not check gets one
 * indistinguishable refusal, a fault is never an answer that lets the request through, and the API's metadata is
 * served by the project for exactly the APIs the proxy checks.
 */
describe('the check a proxy makes before passing a request to an API', () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	describe('an API checked by the proxy', () => {
		const api = once(() =>
			declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' })
		);

		it('a valid token is allowed and the API is told its subject, client and scopes', async () => {
			const target = await api();
			const token = await jwtFor(target, {
				claims: {
					sub: 'account-7',
					client_id: 'agent-7',
					scope: 'files:read files:write'
				}
			});

			const res = await apiCheck({
				slug: w.acme.slug,
				identifier: target.identifier,
				authorization: bearer(token),
				mcpMethod: 'tools/list'
			});

			expect(res.status).toBe(200);
			expect(res.headers.get('x-auth-subject')).toBe('account-7');
			expect(res.headers.get('x-auth-client')).toBe('agent-7');
			expect(res.headers.get('x-auth-scope')).toBe('files:read files:write');
		});

		it("a request without a token is told where the project's metadata is", async () => {
			const target = await api();

			const res = await apiCheck({
				slug: w.acme.slug,
				identifier: target.identifier,
				mcpMethod: 'tools/list'
			});

			expect(res.status).toBe(401);
			expect(res.headers.get('www-authenticate')).toBe(
				`Bearer resource_metadata="${apiCheckUrl(w.acme.slug, target.identifier)}/metadata"`
			);
		});

		it.each([
			['expired', { claims: { exp: Math.floor(Date.now() / 1000) - 60 } }],
			[
				'not yet valid',
				{ claims: { nbf: Math.floor(Date.now() / 1000) + 600 } }
			],
			['signed by a key the project does not hold', { foreignKey: true }],
			[
				'issued by another project',
				{ claims: { iss: 'https://elsewhere.example.com/beta' } }
			],
			[
				'issued for another API',
				{ claims: { aud: 'https://other.example.com/mcp' } }
			],
			['an ID token', { header: { typ: 'JWT' } }]
		] as [string, Minted][])(
			'a token that is %s is refused as invalid',
			async (_what, minted) => {
				const target = await api();

				const res = await apiCheck({
					slug: w.acme.slug,
					identifier: target.identifier,
					authorization: bearer(await jwtFor(target, minted)),
					mcpMethod: 'tools/list'
				});

				expect(res.status).toBe(401);
				expect(res.headers.get('x-auth-reason')).toBe('invalid_token');
				expect(res.headers.get('www-authenticate')).toStartWith(
					'Bearer error="invalid_token", resource_metadata="'
				);
			}
		);

		it('a token signed with another project’s key is refused as invalid', async () => {
			const target = await api();
			const betaApi = await declareApi(w.cookie, w.beta.id, {
				checkedBy: 'proxy'
			});
			const token = await jwtFor(
				{ ...betaApi, identifier: target.identifier },
				{ claims: { iss: target.connection.issuer } }
			);

			const res = await apiCheck({
				slug: w.acme.slug,
				identifier: target.identifier,
				authorization: bearer(token),
				mcpMethod: 'tools/list'
			});

			expect(res.status).toBe(401);
			expect(res.headers.get('x-auth-reason')).toBe('invalid_token');
		});

		it.each([
			['a key-bound self-contained token', 'jwt'],
			['a key-bound opaque token', 'opaque'],
			['the DPoP scheme', 'dpop']
		])('%s is refused as unsupported', async (_what, kind) => {
			const target = await declareApi(w.cookie, w.acme.id, {
				checkedBy: 'proxy',
				tokenFormat: 'opaque'
			});
			const authorization =
				kind === 'jwt'
					? bearer(
							await jwtFor(target, { claims: { cnf: { jkt: 'thumbprint' } } })
						)
					: kind === 'opaque'
						? bearer(
								(await opaqueFor(target, w.acme.id, { jkt: 'thumbprint' }))
									.value
							)
						: `DPoP ${await jwtFor(target)}`;

			const res = await apiCheck({
				slug: w.acme.slug,
				identifier: target.identifier,
				authorization,
				mcpMethod: 'tools/list'
			});

			expect(res.status).toBe(401);
			expect(res.headers.get('x-auth-reason')).toBe('bound_token_unsupported');
		});
	});

	describe('an API with opaque tokens', () => {
		it('a valid opaque token is allowed and the same token after revocation is refused', async () => {
			const target = await declareApi(w.cookie, w.acme.id, {
				checkedBy: 'proxy',
				tokenFormat: 'opaque'
			});
			const token = await opaqueFor(target, w.acme.id, { scope: 'files:read' });
			const send = () =>
				apiCheck({
					slug: w.acme.slug,
					identifier: target.identifier,
					authorization: bearer(token.value),
					mcpMethod: 'tools/list'
				});

			const before = await send();
			await token.revoke();
			const after = await send();

			expect(before.status).toBe(200);
			expect(before.headers.get('x-auth-client')).toBe('agent-1');
			expect(after.status).toBe(401);
			expect(after.headers.get('x-auth-reason')).toBe('invalid_token');
		});
	});

	describe('the project served at the root', () => {
		it("accepts the root's own token for its API at its check", async () => {
			const target = await declareApi(w.cookie, DEFAULT_BUCKET_ID, {
				checkedBy: 'proxy'
			});

			const res = await apiCheck({
				slug: null,
				identifier: target.identifier,
				authorization: bearer(await jwtFor(target)),
				mcpMethod: 'tools/list'
			});

			expect(res.status).toBe(200);
		});
	});

	describe('a token anywhere but the one Authorization header', () => {
		const api = once(() =>
			declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' })
		);

		it.each([
			[
				'a token in the query string',
				async (): Promise<Partial<ApiCheck>> => ({
					query: `?access_token=${await jwtFor(await api())}`
				})
			],
			[
				'two Authorization headers',
				async (): Promise<Partial<ApiCheck>> => {
					const token = await jwtFor(await api());
					return { authorization: [bearer(token), bearer(token)] };
				}
			],
			[
				'a Basic credential',
				async (): Promise<Partial<ApiCheck>> => ({
					authorization: `Basic ${btoa('agent-1:secret')}`
				})
			]
		])('counts as no token: %s', async (_what, input) => {
			const target = await api();

			const res = await apiCheck({
				slug: w.acme.slug,
				identifier: target.identifier,
				mcpMethod: 'tools/list',
				...(await input())
			});

			expect(res.status).toBe(401);
			expect(res.headers.get('x-auth-reason')).toBe('missing_token');
		});
	});

	describe('a check for an API the project does not check', () => {
		const targets = once(async () => {
			const acme = await declareApi(w.cookie, w.acme.id, {
				checkedBy: 'proxy'
			});
			const beta = await declareApi(w.cookie, w.beta.id, {
				checkedBy: 'proxy'
			});
			const ownServer = await declareApi(w.cookie, w.acme.id);
			const doomed = await project('doomed');
			const leaving = await declareApi(w.cookie, doomed.id, {
				checkedBy: 'proxy'
			});
			await scheduleDeletion(doomed.id);
			/* The administrators' project issues no token for any API, so one recorded there by hand is not reachable. */
			const administrators = await getProtectedResourceStore().create({
				namespace: ROOT_NAMESPACE,
				identifier: freshIdentifier(),
				bucketId: ADMIN_BUCKET_ID,
				name: 'Console tools',
				scopes: ['files:read'],
				checkedBy: 'proxy'
			});
			return { acme, beta, ownServer, doomed, leaving, administrators };
		});

		it('every way of naming one gets the same refusal', async () => {
			const t = await targets();
			const token = await jwtFor(t.acme);
			const probes: ApiCheck[] = [
				{ slug: 'nobody-has-this', identifier: t.acme.identifier },
				{ slug: w.acme.slug, identifier: freshIdentifier() },
				{ slug: w.acme.slug, identifier: t.beta.identifier },
				{ slug: w.acme.slug, identifier: t.ownServer.identifier },
				{
					slug: w.acme.slug,
					identifier: t.acme.identifier,
					host: 'evil.example.com'
				},
				{ slug: t.doomed.slug, identifier: t.leaving.identifier },
				{ slug: null, identifier: t.administrators.identifier }
			];

			const answers = await Promise.all(
				probes.map(async (probe) =>
					answerOf(
						await apiCheck({
							...probe,
							authorization: bearer(token),
							mcpMethod: 'tools/list'
						})
					)
				)
			);

			expect(answers[0].status).toBe(403);
			expect(answers[0].headers).toContainEqual(['x-auth-reason', 'not_found']);
			for (const answer of answers.slice(1)) expect(answer).toEqual(answers[0]);
		});
	});

	describe('a fault during the check', () => {
		it('the answer is a server error, never a success', async () => {
			const api = await declareApi(w.cookie, w.acme.id, {
				checkedBy: 'proxy'
			});
			const token = await jwtFor(api);
			const fault = spyOn(
				getProtectedResourceStore(),
				'listByBucket'
			).mockRejectedValue(new Error('the resource store is unavailable'));

			try {
				const res = await apiCheck({
					slug: w.acme.slug,
					identifier: api.identifier,
					authorization: bearer(token),
					mcpMethod: 'tools/list'
				});

				expect(res.status).toBe(500);
			} finally {
				fault.mockRestore();
			}
		});
	});

	describe("the API's metadata", () => {
		it('names the API as resource and the project as authorization server, readable from any origin', async () => {
			const api = await declareApi(w.cookie, w.acme.id, {
				checkedBy: 'proxy'
			});

			const res = await elysia.handle(
				new Request(`${apiCheckUrl(w.acme.slug, api.identifier)}/metadata`)
			);

			expect(res.status).toBe(200);
			expect(res.headers.get('access-control-allow-origin')).toBe('*');
			expect(await res.json()).toMatchObject({
				resource: api.identifier,
				authorization_servers: [api.connection.issuer],
				scopes_supported: api.scopes,
				bearer_methods_supported: ['header']
			});
		});

		it('is not served for an unknown API or one its own server checks, alike', async () => {
			const ownServer = await declareApi(w.cookie, w.acme.id);

			const answers = await Promise.all(
				[ownServer.identifier, freshIdentifier()].map(async (identifier) =>
					answerOf(
						await elysia.handle(
							new Request(`${apiCheckUrl(w.acme.slug, identifier)}/metadata`)
						)
					)
				)
			);

			expect(answers[0].status).toBe(404);
			expect(answers[0].body).toBe('');
			expect(answers[1]).toEqual(answers[0]);
		});
	});

	describe('two APIs of one project', () => {
		it('a token for one is refused at the other', async () => {
			const a = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
			const b = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });

			const res = await apiCheck({
				slug: w.acme.slug,
				identifier: a.identifier,
				authorization: bearer(await jwtFor(b)),
				mcpMethod: 'tools/list'
			});

			expect(res.status).toBe(401);
			expect(res.headers.get('x-auth-reason')).toBe('invalid_token');
		});
	});

	describe('a client that sends identity headers of its own', () => {
		const IDENTITY = ['x-auth-subject', 'x-auth-client', 'x-auth-scope'];
		const forged = {
			'X-Auth-Subject': 'admin',
			'X-Auth-Client': 'trusted-app',
			'X-Auth-Scope': 'files:delete'
		};

		it.each([
			['an allowed request', 'POST'],
			['a preflight', 'OPTIONS']
		])(
			'the answer to %s carries every identity header, so none of the client’s survives',
			async (_what, method) => {
				const api = await declareApi(w.cookie, w.acme.id, {
					checkedBy: 'proxy'
				});

				const res = await apiCheck({
					slug: w.acme.slug,
					identifier: api.identifier,
					method,
					...(method === 'POST'
						? { authorization: bearer(await jwtFor(api)) }
						: {}),
					mcpMethod: 'tools/list',
					headers: {
						...forged,
						...(method === 'OPTIONS'
							? { 'Access-Control-Request-Method': 'POST' }
							: {})
					}
				});

				expect(res.status).toBe(200);
				for (const name of IDENTITY) {
					expect(res.headers.has(name)).toBe(true);
					expect(Object.values(forged)).not.toContain(res.headers.get(name));
				}
			}
		);
	});

	describe('a browser-based client', () => {
		it('a CORS preflight passes without a token', async () => {
			const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });

			const res = await apiCheck({
				slug: w.acme.slug,
				identifier: api.identifier,
				method: 'OPTIONS',
				headers: { 'Access-Control-Request-Method': 'POST' }
			});

			expect(res.status).toBe(200);
			expect(res.headers.get('x-auth-reason')).toBe('preflight');
		});
	});

	describe('checks over one API’s limit', () => {
		afterEach(() => {
			setCheckRateBoundsForTests(null);
			resetCheckRateLimiter();
		});

		it('that API’s checks are slowed and another API’s are not', async () => {
			const flooded = await declareApi(w.cookie, w.acme.id, {
				checkedBy: 'proxy'
			});
			const other = await declareApi(w.cookie, w.acme.id, {
				checkedBy: 'proxy'
			});
			const send = async (api: typeof flooded) =>
				apiCheck({
					slug: w.acme.slug,
					identifier: api.identifier,
					authorization: bearer(await jwtFor(api)),
					mcpMethod: 'tools/list'
				});
			setCheckRateBoundsForTests({ max: 3, windowSeconds: 60 });
			for (let i = 0; i < 3; i++) {
				expect((await send(flooded)).status).toBe(200);
			}

			const slowed = await send(flooded);
			const untouched = await send(other);

			expect(slowed.status).toBe(429);
			expect(slowed.headers.get('x-auth-reason')).toBe('rate_limited');
			expect(untouched.status).toBe(200);
		});
	});

	describe('checks carrying X-Forwarded-For from a proxy the instance trusts', () => {
		const strict = ApplicationConfig['rateLimit.strict.max'];

		afterEach(() => {
			ApplicationConfig['rateLimit.strict.max'] = strict;
			setPeerResolverForTests(null);
			resetUnauthenticatedCharge();
		});

		it('the forwarded address is not the caller address for the instance’s limits', async () => {
			resetUnauthenticatedCharge();
			ApplicationConfig['rateLimit.strict.max'] = 3;
			setPeerResolverForTests(() => '10.0.0.5');
			const probe = (person: number) =>
				apiCheck({
					slug: w.acme.slug,
					identifier: freshIdentifier(),
					headers: { 'X-Forwarded-For': `203.0.113.${String(person)}` }
				});
			for (let person = 1; person <= 3; person++) {
				expect((await probe(person)).status).toBe(403);
			}

			const fourth = await probe(4);

			expect(fourth.status).toBe(429);
		});
	});
});
