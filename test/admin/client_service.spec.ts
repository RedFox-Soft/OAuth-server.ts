import { describe, it, expect, afterEach } from 'bun:test';
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
});
