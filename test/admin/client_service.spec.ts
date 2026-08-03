import { describe, it, expect, afterEach, beforeEach } from 'bun:test';
import {
	createClient,
	getClientView,
	updateClient,
	rotateSecret,
	deleteClientRecord
} from 'lib/admin/clients/service.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

describe('admin client service', () => {
	it('creates a public client (no secret) with derived response types', async () => {
		const { view, secret } = await createClient({
			clientName: 'SPA',
			applicationType: 'web',
			grantTypes: ['authorization_code', 'refresh_token'],
			redirectUris: ['https://app.example.com/cb'],
			tokenEndpointAuthMethod: 'none'
		});
		expect(view.clientId).toBeTruthy();
		expect(view.responseTypes).toEqual(['code']);
		expect(secret).toBeUndefined();
		const reloaded = await getClientView(view.clientId);
		expect(reloaded?.clientName).toBe('SPA');
	});

	it('defaults requireConsent to true when not specified (secure default)', async () => {
		const { view } = await createClient({
			clientName: 'Default Consent',
			grantTypes: ['authorization_code'],
			redirectUris: ['https://consent-default.example.com/cb'],
			tokenEndpointAuthMethod: 'none'
		});
		expect(view.requireConsent).toBe(true);
	});

	it('allows opting out of consent via requireConsent: false', async () => {
		const { view } = await createClient({
			clientName: 'No Consent',
			grantTypes: ['authorization_code'],
			redirectUris: ['https://consent-optout.example.com/cb'],
			tokenEndpointAuthMethod: 'none',
			requireConsent: false
		});
		expect(view.requireConsent).toBe(false);
	});

	it('creates a confidential client and returns the secret once', async () => {
		const { view, secret } = await createClient({
			clientName: 'Server',
			grantTypes: ['client_credentials'],
			tokenEndpointAuthMethod: 'client_secret_basic'
		});
		expect(secret).toBeTruthy();
		// secret is never echoed back through the view
		expect((view as Record<string, unknown>).clientSecret).toBeUndefined();
		const rotated = await rotateSecret(view.clientId);
		expect(rotated).toBeTruthy();
		expect(rotated).not.toBe(secret);
		await deleteClientRecord(view.clientId);
		expect(await getClientView(view.clientId)).toBeNull();
	});

	it('rejects rotating the secret of a public client', async () => {
		const { view } = await createClient({
			grantTypes: ['authorization_code'],
			redirectUris: ['https://a.example.com/cb'],
			tokenEndpointAuthMethod: 'none'
		});
		await expect(rotateSecret(view.clientId)).rejects.toThrow();
	});

	it('updates redirect uris and preserves the secret', async () => {
		const { view, secret } = await createClient({
			grantTypes: ['authorization_code'],
			redirectUris: ['https://one.example.com/cb'],
			tokenEndpointAuthMethod: 'client_secret_basic'
		});
		expect(secret).toBeTruthy();
		const updated = await updateClient(view.clientId, {
			redirectUris: ['https://two.example.com/cb']
		});
		expect(updated.redirectUris).toEqual(['https://two.example.com/cb']);
	});

	it('drops the secret when a confidential client switches to auth method none', async () => {
		const { view, secret } = await createClient({
			grantTypes: ['authorization_code'],
			redirectUris: ['https://three.example.com/cb'],
			tokenEndpointAuthMethod: 'client_secret_basic'
		});
		expect(secret).toBeTruthy();
		const updated = await updateClient(view.clientId, {
			tokenEndpointAuthMethod: 'none'
		});
		expect(updated.tokenEndpointAuthMethod).toBe('none');
		// the stale secret must be gone, so rotate now throws (client is public)
		await expect(rotateSecret(view.clientId)).rejects.toThrow();
	});

	it('mints a secret when a public client switches to a confidential auth method', async () => {
		const { view } = await createClient({
			grantTypes: ['authorization_code'],
			redirectUris: ['https://four.example.com/cb'],
			tokenEndpointAuthMethod: 'none'
		});
		const updated = await updateClient(view.clientId, {
			tokenEndpointAuthMethod: 'client_secret_basic'
		});
		expect(updated.tokenEndpointAuthMethod).toBe('client_secret_basic');
		// no unhandled throw, and the client is now confidential: rotate succeeds
		const rotated = await rotateSecret(view.clientId);
		expect(rotated).toBeTruthy();
	});

	describe('CIBA clients', () => {
		afterEach(() => {
			ApplicationConfig['ciba.enabled'] = false;
		});

		it('creates a CIBA client with a poll delivery mode', async () => {
			ApplicationConfig['ciba.enabled'] = true;
			const { view, secret } = await createClient({
				clientName: 'CIBA Client',
				grantTypes: ['urn:openid:params:grant-type:ciba'],
				tokenEndpointAuthMethod: 'client_secret_basic',
				backchannelTokenDeliveryMode: 'poll'
			});
			expect(secret).toBeTruthy();
			expect(view.backchannelTokenDeliveryMode).toBe('poll');
			const reloaded = await getClientView(view.clientId);
			expect(reloaded?.backchannelTokenDeliveryMode).toBe('poll');
		});
	});

	/*
	 * The per-client permitted RAR types. FR-012 requires every client to opt in explicitly (the client
	 * metadata defaults to []), so without this on the admin surface no client an operator creates could
	 * ever use the feature — the same operator dead end the feature removes at the configuration level.
	 *
	 * These tests exist mainly to catch the silent-drop trap: toMetadata is an explicit allow-list, so a
	 * field added to the request schema alone is accepted by the route and then discarded here, and
	 * toView must read it back or it never surfaces.
	 */
	describe('authorizationDetailsTypes', () => {
		const PAYMENT = 'https://scheme.example/payment';

		beforeEach(() => {
			ApplicationConfig['richAuthorizationRequests.enabled'] = true;
			ApplicationConfig['richAuthorizationRequests.types'] = {
				[PAYMENT]: { label: 'Initiate a payment' }
			};
		});

		afterEach(() => {
			ApplicationConfig['richAuthorizationRequests.enabled'] = false;
			ApplicationConfig['richAuthorizationRequests.types'] = {};
		});

		it('persists the field on create and reads it back', async () => {
			const { view } = await createClient({
				clientName: 'RAR client',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://rar-create.example.com/cb'],
				tokenEndpointAuthMethod: 'none',
				authorizationDetailsTypes: [PAYMENT]
			});

			expect(view.authorizationDetailsTypes).toEqual([PAYMENT]);
			const reloaded = await getClientView(view.clientId);
			expect(reloaded?.authorizationDetailsTypes).toEqual([PAYMENT]);
		});

		it('updates the field and preserves it across an unrelated patch', async () => {
			const { view } = await createClient({
				clientName: 'RAR update',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://rar-update.example.com/cb'],
				tokenEndpointAuthMethod: 'none'
			});
			expect(view.authorizationDetailsTypes ?? []).toEqual([]);

			const updated = await updateClient(view.clientId, {
				authorizationDetailsTypes: [PAYMENT]
			});
			expect(updated.authorizationDetailsTypes).toEqual([PAYMENT]);

			const afterUnrelated = await updateClient(view.clientId, {
				clientName: 'Renamed'
			});
			expect(afterUnrelated.authorizationDetailsTypes).toEqual([PAYMENT]);
		});

		// Delegated validation: the type must be one the server is configured to accept.
		it('refuses a type that is not configured', async () => {
			await expect(
				createClient({
					clientName: 'RAR bad type',
					grantTypes: ['authorization_code'],
					redirectUris: ['https://rar-bad.example.com/cb'],
					tokenEndpointAuthMethod: 'none',
					authorizationDetailsTypes: ['https://scheme.example/nope']
				})
			).rejects.toThrow();
		});

		/*
		 * With the feature disabled the metadata is not recognized at all, and the client schema drops
		 * unrecognized metadata rather than refusing it — the standard dynamic-registration treatment,
		 * which the admin surface inherits because validation is delegated rather than restated. So the
		 * field is accepted and ignored, not rejected. Pinned because "accepted" reads as "stored" to
		 * an operator, and it is the one rough edge of delegating here.
		 */
		it('ignores the field when the feature is disabled, rather than refusing it', async () => {
			ApplicationConfig['richAuthorizationRequests.enabled'] = false;
			ApplicationConfig['richAuthorizationRequests.types'] = {};

			const { view } = await createClient({
				clientName: 'RAR off',
				grantTypes: ['authorization_code'],
				redirectUris: ['https://rar-off.example.com/cb'],
				tokenEndpointAuthMethod: 'none',
				authorizationDetailsTypes: [PAYMENT]
			});

			expect(view.authorizationDetailsTypes).toBeUndefined();
			const reloaded = await getClientView(view.clientId);
			expect(reloaded?.authorizationDetailsTypes).toBeUndefined();
		});
	});
});
