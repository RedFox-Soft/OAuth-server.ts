import { describe, it, beforeEach, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ApplicationConfig } from 'lib/configs/application.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { gatedRoutes } from 'lib/consts/route_classification.js';
import { TestAdapter } from 'test/models.js';
import { expectUnservedEquivalent, send } from './helpers.js';

const json = { 'content-type': 'application/json' };
const form = { 'content-type': 'application/x-www-form-urlencoded' };

const registrationBody = JSON.stringify({
	redirect_uris: ['https://rp.example.com/cb']
});

function storedClientIds(): string[] {
	return [...TestAdapter.for('Client').store.keys()].filter((key: string) =>
		key.startsWith('Client:')
	);
}

describe('feature gate — capability off', () => {
	beforeEach(async () => {
		await bootstrap(import.meta.url);
	});

	describe('registration', () => {
		it('refuses anonymous client registration on a default deployment', async () => {
			expect(ApplicationConfig['registration.enabled']).toBe(false);

			const before = storedClientIds();

			await expectUnservedEquivalent('/reg', {
				method: 'POST',
				headers: json,
				body: registrationBody
			});

			expect(storedClientIds()).toEqual(before);
		});

		it('refuses reading a client configuration', async () => {
			await expectUnservedEquivalent('/reg/any-client-id', { method: 'GET' });
		});
	});

	describe('registration management', () => {
		beforeEach(() => {
			ApplicationConfig['registration.enabled'] = true;
			ApplicationConfig['registrationManagement.enabled'] = false;
		});

		it('refuses update and delete on the client configuration path', async () => {
			await expectUnservedEquivalent('/reg/any-client-id', {
				method: 'PUT',
				headers: json,
				body: registrationBody
			});
			await expectUnservedEquivalent('/reg/any-client-id', {
				method: 'DELETE'
			});
		});

		// The read follows `registration`, which is on here — so it must NOT be a gate refusal. It
		// fails on the missing registration access token instead, which is the pre-existing
		// behaviour and the whole point of gating per method rather than per path.
		it('leaves the read reachable because registration itself is on', async () => {
			const read = await send('/reg/any-client-id', { method: 'GET' });

			expect(read.status).toBe(400);
		});
	});

	/*
	 * The probe shapes that would otherwise reveal the endpoint. Each must answer exactly as the
	 * unserved path does — no auth challenge for an endpoint that requires client authentication, no
	 * validation complaint describing a request contract the caller is not entitled to learn.
	 */
	describe('leaking nothing under probing', () => {
		const authRequired = [
			{ path: '/token/introspect', flag: 'introspection.enabled' },
			{ path: '/token/revocation', flag: 'revocation.enabled' }
		] as const;

		for (const { path, flag } of authRequired) {
			describe(`${path} (${flag} off)`, () => {
				it('answers without an authentication challenge when credentials are absent', async () => {
					const res = await expectUnservedEquivalent(path, {
						method: 'POST',
						headers: form,
						body: 'token=whatever'
					});

					expect(res.headers['www-authenticate']).toBeUndefined();
				});

				it('answers identically for a body that violates the route schema', async () => {
					await expectUnservedEquivalent(path, {
						method: 'POST',
						headers: form,
						body: 'not_the_expected_field=1'
					});
				});

				it('answers identically for the wrong content type', async () => {
					await expectUnservedEquivalent(path, {
						method: 'POST',
						headers: json,
						body: JSON.stringify({ token: 'whatever' })
					});
				});

				it('answers identically even with valid client credentials', async () => {
					await expectUnservedEquivalent(path, {
						method: 'POST',
						headers: {
							...form,
							authorization: `Basic ${Buffer.from('client:secret').toString('base64')}`
						},
						body: 'token=whatever'
					});
				});
			});
		}
	});

	/*
	 * Browser-facing gated endpoints. Before this feature an HTML-preferring request to *any*
	 * unserved path answered 200, because the error page was built without a status — so these two
	 * cases fail until that is corrected.
	 */
	describe('HTML-preferring callers', () => {
		const html = { accept: 'text/html' };

		it('refuses the logout endpoint with a real 404', async () => {
			await expectUnservedEquivalent('/logout', {
				method: 'GET',
				headers: html
			});
		});

		it('refuses the user-code page with a real 404', async () => {
			await expectUnservedEquivalent('/device', {
				method: 'GET',
				headers: html
			});
		});
	});

	/*
	 * Driven off the classification table rather than a hand-written list, so a sixteenth gated entry
	 * is covered the moment it is declared.
	 */
	describe('every gated entry', () => {
		for (const route of gatedRoutes) {
			const path = route.path.replace(':clientId', 'some-client-id');

			it(`refuses ${route.method} ${route.path} while ${route.flag} is off`, async () => {
				expect(ApplicationConfig[route.flag]).toBeFalsy();

				await expectUnservedEquivalent(path, { method: route.method });
			});
		}
	});

	/*
	 * The two entry points that consulted only the calling client's own metadata. The client below is
	 * permitted both grants, so a 404 here proves the server flag is consulted first (FR-008).
	 */
	describe('server flag ahead of client metadata', () => {
		const credentials = {
			...form,
			authorization: `Basic ${Buffer.from('client-device:secret').toString('base64')}`
		};

		it('refuses device authorization for a device-grant client', async () => {
			await expectUnservedEquivalent('/device/auth', {
				method: 'POST',
				headers: credentials,
				body: 'client_id=client-device&scope=openid'
			});
		});

		it('refuses backchannel authentication for a CIBA client', async () => {
			await expectUnservedEquivalent('/backchannel', {
				method: 'POST',
				headers: credentials,
				body: 'client_id=client-device&scope=openid&login_hint=accountId'
			});
		});
	});

	it('refuses userinfo even for a request bearing a valid access token', async () => {
		const token = await new AccessToken({
			accountId: 'accountId',
			grantId: 'grantId',
			client: await Client.find('client'),
			scope: 'openid'
		}).save();

		const res = await expectUnservedEquivalent('/userinfo', {
			method: 'GET',
			headers: { authorization: `Bearer ${token}` }
		});

		expect(res.headers['www-authenticate']).toBeUndefined();
	});

	// FR-005 covers more than tokens: the two browser-facing gated endpoints run session and
	// interaction handling when enabled, so a refusal must not start either.
	it('starts no session or interaction when a browser-facing endpoint is refused', async () => {
		const countKeys = (prefix: string) =>
			[...TestAdapter.for(prefix).store.keys()].filter((key: string) =>
				key.startsWith(`${prefix}:`)
			).length;

		const before = {
			Session: countKeys('Session'),
			Interaction: countKeys('Interaction')
		};

		await send('/logout', { method: 'GET', headers: { accept: 'text/html' } });
		await send('/device', { method: 'GET', headers: { accept: 'text/html' } });
		await send('/device', {
			method: 'POST',
			headers: form,
			body: 'user_code=ABCD-EFGH'
		});

		expect({
			Session: countKeys('Session'),
			Interaction: countKeys('Interaction')
		}).toEqual(before);
	});

	it('leaves a valid token untouched when revocation is refused', async () => {
		const token = await new AccessToken({
			accountId: 'accountId',
			grantId: 'grantId',
			client: await Client.find('client'),
			scope: 'openid'
		}).save();

		await expectUnservedEquivalent('/token/revocation', {
			method: 'POST',
			headers: {
				...form,
				authorization: `Basic ${Buffer.from('client:secret').toString('base64')}`
			},
			body: `token=${token}`
		});

		const stillThere = await AccessToken.find(token);
		expect(stillThere).toBeDefined();
		expect(stillThere?.isValid).toBe(true);
	});
});
