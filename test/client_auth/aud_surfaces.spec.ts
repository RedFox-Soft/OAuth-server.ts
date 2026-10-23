import { describe, it, beforeAll, afterAll, expect, mock } from 'bun:test';
import { providerError } from 'test/shape.ts';
import { eventBus, type ServerListener } from 'lib/event_bus.js';
import { importJWK } from 'jose';

import * as JWT from '../../lib/helpers/jwt.ts';
import bootstrap, { agent, formAgent } from '../test_helper.js';
import nanoid from 'lib/helpers/nanoid.js';
import { ISSUER } from 'lib/configs/env.js';
import { Client, clientKeys } from 'lib/models/client.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { routeNames } from 'lib/consts/param_list.js';

const CLIENT = 'client-jwt-secret';
const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

/*
 * Every endpoint on this server that authenticates a client. The typed HTTP client cannot build a
 * path from a string, so this is a table of real calls rather than a walk of the route table — and
 * the first case below is what keeps it honest: each entry must actually refuse an unauthenticated
 * request, so an endpoint that never authenticated anybody cannot sit here inflating the claim.
 */
const ENDPOINTS = [
	{
		name: routeNames.token,
		send: (extra: Record<string, unknown>) =>
			agent.token.post({ grant_type: 'client_credentials', ...extra })
	},
	{
		name: routeNames.introspect,
		send: (extra: Record<string, unknown>) =>
			agent.token.introspect.post({ token: 'foo', ...extra })
	},
	{
		name: routeNames.revocation,
		send: (extra: Record<string, unknown>) =>
			agent.token.revocation.post({ token: 'foo', ...extra })
	},
	{
		name: routeNames.pushed_authorization_request,
		send: (extra: Record<string, unknown>) =>
			agent.par.post({
				response_type: 'code',
				scope: 'openid',
				...extra
			})
	},
	{
		name: routeNames.device_authorization,
		send: (extra: Record<string, unknown>) =>
			formAgent.device.auth.post({ scope: 'openid', ...extra })
	},
	{
		name: routeNames.backchannel_authentication,
		send: (extra: Record<string, unknown>) =>
			formAgent.backchannel.post({
				scope: 'openid',
				login_hint: 'accountId',
				...extra
			})
	}
];

function unauthenticated(status: number) {
	return status === 400 || status === 401;
}

/**
 * @proves Where a captured client assertion can be spent is bounded at every endpoint that accepts
 * one rather than only at the token endpoint: each accepts the audiences RFC 9126 §2 and CIBA §7.1
 * require a server to accept, refuses one naming somebody else, and — once the operator turns on
 * the rfc7523bis rule — accepts the issuer identifier alone.
 */
describe('client assertion audience, at every endpoint that authenticates a client', () => {
	let key: Awaited<ReturnType<typeof importJWK>>;
	const flags = [
		'par.enabled',
		'revocation.enabled',
		'deviceFlow.enabled',
		'ciba.enabled'
	] satisfies Array<keyof typeof ApplicationConfig>;
	const restore: Array<[(typeof flags)[number], boolean]> = [];

	beforeAll(async function () {
		await bootstrap(import.meta.url, { config: 'client_auth' });

		// All four are off by default; the endpoints are gated on them, so without this four of the six
		// entries below answer 404 and the guard correctly calls the set dishonest.
		for (const flag of flags) {
			restore.push([flag, ApplicationConfig[flag]]);
			ApplicationConfig[flag] = true;
		}

		key = await importJWK(
			clientKeys(await Client.find(CLIENT)).symmetric.selectForSign({
				alg: 'HS256'
			})[0]
		);
	});

	afterAll(function () {
		for (const [flag, value] of restore) {
			ApplicationConfig[flag] = value;
		}
	});

	function assertion(aud: string | string[]) {
		return JWT.sign(
			{ jti: nanoid(), aud, sub: CLIENT, iss: CLIENT },
			key,
			'HS256',
			{ expiresIn: 60 }
		);
	}

	it('refuses an unauthenticated request at every endpoint listed as client-authenticated', async function () {
		for (const { name, send } of ENDPOINTS) {
			const { status } = await send({});
			expect(
				unauthenticated(status),
				`${name} accepted a request carrying no client credentials`
			).toBe(true);
		}
	});

	it('accepts an assertion audienced at the issuer identifier at every one of them', async function () {
		for (const { name, send } of ENDPOINTS) {
			const { status } = await send({
				client_assertion: await assertion(ISSUER),
				client_assertion_type: ASSERTION_TYPE
			});
			expect(
				status,
				`${name} refused an assertion audienced at the issuer`
			).not.toBe(401);
		}
	});

	it('accepts an assertion audienced at the token endpoint url at every one of them', async function () {
		for (const { name, send } of ENDPOINTS) {
			const { status } = await send({
				client_assertion: await assertion(`${ISSUER}${routeNames.token}`),
				client_assertion_type: ASSERTION_TYPE
			});
			expect(
				status,
				`${name} refused an assertion audienced at the token endpoint`
			).not.toBe(401);
		}
	});

	it('refuses an assertion audienced at another server at every one of them', async function () {
		for (const { name, send } of ENDPOINTS) {
			const { status } = await send({
				client_assertion: await assertion('https://someone-else.example.com'),
				client_assertion_type: ASSERTION_TYPE
			});
			expect(
				status,
				`${name} accepted an assertion meant for another server`
			).toBe(401);
		}
	});

	it("accepts an assertion audienced at the endpoint's own url at every one of them", async function () {
		for (const { name, send } of ENDPOINTS) {
			const { status } = await send({
				client_assertion: await assertion(`${ISSUER}${name}`),
				client_assertion_type: ASSERTION_TYPE
			});
			expect(
				status,
				`${name} refused an assertion audienced at its own url`
			).not.toBe(401);
		}
	});

	it('refuses an audience built from an internal name rather than a url of this server', async function () {
		const internal = [
			[routeNames.device_authorization, `${ISSUER}anonymous`],
			[
				routeNames.backchannel_authentication,
				`${ISSUER}backchannel_authentication`
			]
		];
		for (const [name, aud] of internal) {
			const endpoint = ENDPOINTS.find((entry) => entry.name === name);
			if (!endpoint) throw new Error(`${name} is not in the endpoint table`);
			const { status } = await endpoint.send({
				client_assertion: await assertion(aud),
				client_assertion_type: ASSERTION_TYPE
			});
			expect(status, `${name} accepted ${aud}`).toBe(401);
		}
	});

	/*
	 * draft-ietf-oauth-rfc7523bis §4 item 3b: the issuer identifier is the sole audience, and the token
	 * endpoint url "MUST NOT be used". Off by default while RFC 9126 §2 and CIBA §7.1 still require the
	 * other values, so these cases switch it on.
	 */
	describe('while the issuer-only rule is on', () => {
		beforeAll(function () {
			ApplicationConfig['clientAuth.issuerOnlyAudience'] = true;
		});

		afterAll(function () {
			ApplicationConfig['clientAuth.issuerOnlyAudience'] = false;
		});

		it('accepts an assertion audienced at the issuer identifier at every one of them', async function () {
			for (const { name, send } of ENDPOINTS) {
				const { status } = await send({
					client_assertion: await assertion(ISSUER),
					client_assertion_type: ASSERTION_TYPE
				});
				expect(
					status,
					`${name} refused an assertion audienced at the issuer`
				).not.toBe(401);
			}
		});

		it('accepts the issuer identifier as a one-element list at every one of them', async function () {
			for (const { name, send } of ENDPOINTS) {
				const { status } = await send({
					client_assertion: await assertion([ISSUER]),
					client_assertion_type: ASSERTION_TYPE
				});
				expect(status, `${name} refused [issuer] as the audience`).not.toBe(
					401
				);
			}
		});

		it('refuses an assertion audienced at the token endpoint url at every one of them', async function () {
			for (const { name, send } of ENDPOINTS) {
				const { status } = await send({
					client_assertion: await assertion(`${ISSUER}${routeNames.token}`),
					client_assertion_type: ASSERTION_TYPE
				});
				expect(
					status,
					`${name} accepted the token endpoint url as the audience`
				).toBe(401);
			}
		});

		it("refuses an assertion audienced at the endpoint's own url at every one of them", async function () {
			for (const { name, send } of ENDPOINTS.filter(
				(endpoint) => endpoint.name !== routeNames.token
			)) {
				const { status } = await send({
					client_assertion: await assertion(`${ISSUER}${name}`),
					client_assertion_type: ASSERTION_TYPE
				});
				expect(status, `${name} accepted its own url as the audience`).toBe(
					401
				);
			}
		});

		it('refuses an audience that lists the issuer and another value at every one of them', async function () {
			for (const { name, send } of ENDPOINTS) {
				const { status } = await send({
					client_assertion: await assertion([
						ISSUER,
						'https://someone-else.example.com'
					]),
					client_assertion_type: ASSERTION_TYPE
				});
				expect(
					status,
					`${name} accepted an audience shared with another party`
				).toBe(401);
			}
		});

		it('refuses the issuer identifier written with a trailing slash', async function () {
			const { status } = await agent.token.post({
				grant_type: 'client_credentials',
				client_assertion: await assertion(`${ISSUER}/`),
				client_assertion_type: ASSERTION_TYPE
			});
			expect(status).toBe(401);
		});

		it('names the issuer-only rule in the reason for a refusal', async function () {
			const spy = mock<ServerListener<'grant.error'>>();
			eventBus.once('grant.error', spy);

			await agent.token.post({
				grant_type: 'client_credentials',
				client_assertion: await assertion(`${ISSUER}${routeNames.token}`),
				client_assertion_type: ASSERTION_TYPE
			});

			expect(providerError(spy.mock.calls[0][0]).error_detail).toBe(
				'audience (aud) must be the issuer identifier as its sole value'
			);
		});
	});

	it('refuses the token endpoint url on the next request after the issuer-only rule is switched on, with no restart', async function () {
		await agent.token.post({
			grant_type: 'client_credentials',
			client_assertion: await assertion(`${ISSUER}${routeNames.token}`),
			client_assertion_type: ASSERTION_TYPE
		});
		ApplicationConfig['clientAuth.issuerOnlyAudience'] = true;
		try {
			const { status } = await agent.token.post({
				grant_type: 'client_credentials',
				client_assertion: await assertion(`${ISSUER}${routeNames.token}`),
				client_assertion_type: ASSERTION_TYPE
			});
			expect(status).toBe(401);
		} finally {
			ApplicationConfig['clientAuth.issuerOnlyAudience'] = false;
		}
	});
});
