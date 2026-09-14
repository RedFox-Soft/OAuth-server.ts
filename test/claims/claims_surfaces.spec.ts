import { describe, it, beforeAll, expect } from 'bun:test';

import bootstrap, {
	agent,
	jsonToFormUrlEncoded,
	type Setup
} from '../test_helper.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import * as paramList from 'lib/consts/param_list.js';

const UNKNOWN_MEMBER = { urn_example_ext: { anything: true } };
const basic = AuthorizationRequest.basicAuthHeader('client', 'secret');
const form = { ['content-type']: 'application/x-www-form-urlencoded' };

const DEFINED = { id_token: { email: null } };

function claims(withUnknown: boolean) {
	return JSON.stringify(
		withUnknown ? { ...DEFINED, ...UNKNOWN_MEMBER } : DEFINED
	);
}

function refusedForClaims(body: unknown): boolean {
	return JSON.stringify(body ?? '').includes('claims');
}

/*
 * A TypeBox object schema that declares a top-level `claims` member. Discovered rather than listed,
 * so a surface somebody adds later shows up here instead of going unnoticed.
 */
function declaresClaims(value: unknown): boolean {
	return (
		typeof value === 'object' &&
		value !== null &&
		'properties' in value &&
		typeof (value as { properties?: unknown }).properties === 'object' &&
		(value as { properties: Record<string, unknown> }).properties?.claims !==
			undefined
	);
}

/**
 * @proves A member the server does not define inside the `claims` request value is ignored at every
 * surface that accepts `claims`, and no surface reintroduces a closed `claims` object.
 */
describe('unknown claims members across every surface that accepts claims', () => {
	let setup: Setup;

	beforeAll(async function () {
		setup = await bootstrap(import.meta.url, { config: 'claims_surfaces' });
	});

	/*
	 * The completeness half. The behavioural cases below drive the endpoints one by one, which can
	 * only ever cover the surfaces somebody remembered to write a case for; this enumerates the
	 * request schemas the server actually mounts and fails when one of them closes `claims` again.
	 * `/par` is covered by AuthorizationParameters: its body schema is built by spreading that
	 * object's properties, so it carries the same `claims` schema object rather than a copy.
	 */
	it('declares no schema that refuses an undefined member of the claims object', () => {
		const schemas = Object.entries(paramList).filter(([, value]) =>
			declaresClaims(value)
		);

		expect(schemas.length).toBeGreaterThan(0);

		const closed = schemas
			.filter(([, value]) => {
				const claims = (
					value as { properties: Record<string, Record<string, unknown>> }
				).properties.claims;
				return JSON.stringify(claims).includes('"additionalProperties":false');
			})
			.map(([name]) => name);

		expect(closed).toEqual([]);
	});

	/*
	 * Each case below sends the same request twice, once carrying a member the server does not define
	 * and once without it, and requires the two answers to match. That is FR-001 stated directly —
	 * "answered exactly as it would be with the member removed" — and it holds the claim without
	 * depending on whatever else a given endpoint needs in order to succeed, which differs per surface
	 * and is not what these cases are about.
	 */
	it('answers the authorization endpoint the same with and without an undefined claims member', async function () {
		const cookie = await setup.login();

		const withMember = new AuthorizationRequest({
			scope: 'openid',
			claims: { ...DEFINED, ...UNKNOWN_MEMBER }
		});
		const without = new AuthorizationRequest({
			scope: 'openid',
			claims: DEFINED
		});

		const a = await agent.auth.get({
			query: withMember.params,
			headers: { cookie }
		});
		const b = await agent.auth.get({
			query: without.params,
			headers: { cookie }
		});

		expect(a.response.status).toBe(b.response.status);
		expect(refusedForClaims(a.error?.value)).toBe(false);
	});

	it('answers the pushed authorization request endpoint the same with and without an undefined claims member', async function () {
		const send = (withUnknown: boolean) =>
			agent.par.post(
				// @ts-expect-error endpoint parses form-url-encoded into an object
				jsonToFormUrlEncoded({
					client_id: 'client',
					response_type: 'code',
					redirect_uri: 'https://client.example.com/cb',
					scope: 'openid',
					claims: claims(withUnknown)
				}),
				{ headers: { ...form, ...basic } }
			);

		const a = await send(true);
		const b = await send(false);

		expect(a.response.status).toBe(b.response.status);
		expect(refusedForClaims(a.error?.value)).toBe(false);
	});

	it('answers the device authorization endpoint the same with and without an undefined claims member', async function () {
		const send = (withUnknown: boolean) =>
			agent.device.auth.post(
				// @ts-expect-error endpoint parses form-url-encoded into an object
				jsonToFormUrlEncoded({
					client_id: 'client',
					scope: 'openid',
					claims: claims(withUnknown)
				}),
				{ headers: { ...form, ...basic } }
			);

		const a = await send(true);
		const b = await send(false);

		expect(a.response.status).toBe(b.response.status);
		expect(refusedForClaims(a.error?.value)).toBe(false);
	});

	it('answers the backchannel authentication endpoint the same with and without an undefined claims member', async function () {
		await setup.login();
		const { accountId } = setup.getSession();

		const send = (withUnknown: boolean) =>
			agent.backchannel.post(
				// @ts-expect-error endpoint parses form-url-encoded into an object
				jsonToFormUrlEncoded({
					client_id: 'client',
					scope: 'openid',
					login_hint: accountId,
					claims: claims(withUnknown)
				}),
				{ headers: { ...form, ...basic } }
			);

		const a = await send(true);
		const b = await send(false);

		expect(a.response.status).toBe(b.response.status);
		expect(refusedForClaims(a.error?.value)).toBe(false);
	});
});
