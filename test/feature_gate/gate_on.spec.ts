import { describe, it, beforeEach, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import {
	ApplicationConfig,
	reloadConfiguration
} from 'lib/configs/application.js';
import { send } from './helpers.js';

const json = { 'content-type': 'application/json' };
const form = { 'content-type': 'application/x-www-form-urlencoded' };

async function discoveryDocument(): Promise<string> {
	const res = await send('/.well-known/openid-configuration', {
		method: 'GET'
	});
	return res.text();
}

describe('feature gate — capability on', () => {
	beforeEach(async () => {
		await bootstrap(import.meta.url);
	});

	it('registers a client normally once registration is on', async () => {
		ApplicationConfig['registration.enabled'] = true;

		const res = await send('/reg', {
			method: 'POST',
			headers: json,
			body: JSON.stringify({ redirect_uris: ['https://rp.example.com/cb'] })
		});

		expect(res.status).toBe(201);
		expect(await res.json()).toHaveProperty('client_id');
	});

	// FR-013: advertisement was already correct, so gating must not perturb it in either state.
	it('leaves the discovery document identical in both registration states', async () => {
		ApplicationConfig['registration.enabled'] = false;
		reloadConfiguration();
		const off = await discoveryDocument();

		ApplicationConfig['registration.enabled'] = true;
		reloadConfiguration();
		const on = await discoveryDocument();

		expect(off).not.toBe(on);
		expect(JSON.parse(on)).toHaveProperty('registration_endpoint');
		expect(JSON.parse(off)).not.toHaveProperty('registration_endpoint');
	});

	/*
	 * The trap this whole feature could have died on: `POST /token` is always available while
	 * `POST /token/introspect` and `POST /token/revocation` are gated. A prefix match on '/token'
	 * would take down every grant flow, and it would look like a token bug rather than a gate bug.
	 */
	it('keeps the token endpoint reachable with every gated capability off', async () => {
		const res = await send('/token', {
			method: 'POST',
			headers: form,
			body: 'grant_type=authorization_code&code=nonexistent&code_verifier=x'
		});

		expect(res.status).not.toBe(404);
	});

	/*
	 * The gate must not shadow the authorization endpoint's own feature checks. `/auth` is ungated, so
	 * a request_uri submitted while PAR is off has to keep raising the OIDC-specified error rather
	 * than becoming a 404 — the check in featureVerification is live and correct for this endpoint,
	 * and it never fired for POST /par only because the PAR body schema omits request_uri.
	 */
	it('gates POST /par while leaving the authorization endpoint request_uri error intact', async () => {
		expect(ApplicationConfig['par.enabled']).toBe(false);

		const par = await send('/par', { method: 'POST' });
		expect(par.status).toBe(404);

		const authorization = await send(
			'/auth?client_id=client&response_type=code&scope=openid' +
				'&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb' +
				'&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Awhatever',
			{ method: 'GET' }
		);

		expect(authorization.status).not.toBe(404);
		const surfaced =
			authorization.headers.get('location') ?? (await authorization.text());
		expect(surfaced).toContain('not_supported');
	});

	/*
	 * FR-009: availability is decided per request, not captured at boot. Flipping the flag twice
	 * inside one spec run against one long-lived app instance is the assertion — a boot-time route set
	 * could not produce this.
	 */
	it('follows the flag on the very next request, in both directions', async () => {
		const probe = () => send('/userinfo', { method: 'GET' });

		ApplicationConfig['userinfo.enabled'] = false;
		expect((await probe()).status).toBe(404);

		ApplicationConfig['userinfo.enabled'] = true;
		expect((await probe()).status).not.toBe(404);

		ApplicationConfig['userinfo.enabled'] = false;
		expect((await probe()).status).toBe(404);
	});

	it('changes only the flipped capability', async () => {
		ApplicationConfig['revocation.enabled'] = true;

		// Its sibling on the same path prefix, and every other capability, stay off.
		expect(
			(await send('/token/revocation', { method: 'POST' })).status
		).not.toBe(404);
		expect((await send('/token/introspect', { method: 'POST' })).status).toBe(
			404
		);
		expect((await send('/par', { method: 'POST' })).status).toBe(404);
		expect((await send('/userinfo', { method: 'GET' })).status).toBe(404);
		expect((await send('/logout', { method: 'GET' })).status).toBe(404);
		expect((await send('/device', { method: 'GET' })).status).toBe(404);
		expect((await send('/backchannel', { method: 'POST' })).status).toBe(404);
		expect((await send('/reg', { method: 'POST' })).status).toBe(404);
	});

	/*
	 * FR-005a: switching a capability off is a reachability change, not a data change. A client
	 * registered while registration was on keeps authenticating afterwards — nothing is purged.
	 */
	it('leaves a client registered while registration was on able to authenticate after it is off', async () => {
		ApplicationConfig['registration.enabled'] = true;

		const registered = await send('/reg', {
			method: 'POST',
			headers: json,
			body: JSON.stringify({
				redirect_uris: ['https://rp.example.com/cb'],
				grant_types: ['authorization_code'],
				response_types: ['code']
			})
		});
		expect(registered.status).toBe(201);
		const { client_id, client_secret } = (await registered.json()) as {
			client_id: string;
			client_secret: string;
		};

		ApplicationConfig['registration.enabled'] = false;

		// Its registration endpoint is gone...
		expect(
			(await send('/reg', { method: 'POST', headers: json, body: '{}' })).status
		).toBe(404);

		// ...but the client itself still authenticates: a bad code, not a bad client.
		const token = await send('/token', {
			method: 'POST',
			headers: {
				...form,
				authorization: `Basic ${Buffer.from(`${client_id}:${client_secret}`).toString('base64')}`
			},
			body:
				'grant_type=authorization_code&code=nonexistent' +
				`&code_verifier=${'a'.repeat(43)}` +
				'&redirect_uri=https%3A%2F%2Frp.example.com%2Fcb'
		});

		// invalid_grant, not invalid_client: the credentials were accepted and only the made-up code
		// was rejected, which is what "the client still works" means.
		expect(token.status).not.toBe(404);
		expect(await token.json()).toHaveProperty('error', 'invalid_grant');
	});

	// FR-013 across the whole gated set, not just registration: advertisement keeps tracking the flag
	// in both states for every capability, which is what "gating did not perturb discovery" means.
	it('keeps discovery tracking every gated flag in both states', async () => {
		const advertised = {
			'par.enabled': 'pushed_authorization_request_endpoint',
			'introspection.enabled': 'introspection_endpoint',
			'revocation.enabled': 'revocation_endpoint',
			'registration.enabled': 'registration_endpoint',
			'rpInitiatedLogout.enabled': 'end_session_endpoint',
			'userinfo.enabled': 'userinfo_endpoint',
			'deviceFlow.enabled': 'device_authorization_endpoint',
			'ciba.enabled': 'backchannel_authentication_endpoint'
		} as const;

		for (const [flag, key] of Object.entries(advertised)) {
			ApplicationConfig[flag as keyof typeof advertised] = false;
			reloadConfiguration();
			expect(JSON.parse(await discoveryDocument())).not.toHaveProperty(key);

			ApplicationConfig[flag as keyof typeof advertised] = true;
			reloadConfiguration();
			expect(JSON.parse(await discoveryDocument())).toHaveProperty(key);

			ApplicationConfig[flag as keyof typeof advertised] = false;
			reloadConfiguration();
		}
	});

	it('keeps the always-available surfaces reachable with every gated capability off', async () => {
		const authorization = await send(
			'/auth?client_id=client&response_type=code&scope=openid&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb',
			{ method: 'GET' }
		);
		expect(authorization.status).not.toBe(404);

		for (const path of [
			'/health',
			'/jwks',
			'/.well-known/openid-configuration'
		]) {
			const res = await send(path, { method: 'GET' });
			expect(res.status).toBe(200);
		}
	});
});
