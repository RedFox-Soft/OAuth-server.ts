import { describe, it, beforeAll, afterAll, expect } from 'bun:test';
import { importJWK } from 'jose';

import * as JWT from '../../lib/helpers/jwt.ts';
import bootstrap, { agent } from '../test_helper.js';
import nanoid from 'lib/helpers/nanoid.js';
import { ISSUER } from 'lib/configs/env.js';
import { Client } from 'lib/models/client.js';
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
	}
];

function unauthenticated(status: number) {
	return status === 400 || status === 401;
}

/**
 * @proves Where a captured client assertion can be spent is bounded at every endpoint that accepts
 * one rather than only at the token endpoint: each accepts the audiences RFC 9126 §2.1 requires a
 * server to accept, and refuses one naming somebody else.
 */
describe('client assertion audience, at every endpoint that authenticates a client', () => {
	let key: Awaited<ReturnType<typeof importJWK>>;
	const restore: Array<[string, unknown]> = [];

	beforeAll(async function () {
		await bootstrap(import.meta.url, { config: 'client_auth' });

		// Both are off by default; the endpoints are gated on them, so without this two of the four
		// entries below answer 404 and the guard correctly calls the set dishonest.
		for (const flag of ['par.enabled', 'revocation.enabled']) {
			restore.push([flag, ApplicationConfig[flag]]);
			ApplicationConfig[flag] = true;
		}

		key = await importJWK(
			(await Client.find(CLIENT)).symmetricKeyStore.selectForSign({
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
});
