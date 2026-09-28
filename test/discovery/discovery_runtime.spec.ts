import { describe, it, beforeAll, afterAll, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { ApplicationConfig } from '../../lib/configs/application.js';
import { present } from '../shape.js';

const endpoint = async () =>
	present(
		(await agent['.well-known']['openid-configuration'].get()).data,
		'the discovery document'
	);

/**
 * @proves A runtime flag change is reflected in the discovery document without a restart.
 */
describe('discovery runtime mutability', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	afterAll(() => {
		ApplicationConfig['deviceFlow.enabled'] = false;
		ApplicationConfig['clientCredentials.enabled'] = false;
		ApplicationConfig.scopes = ['openid', 'offline_access'];
	});

	it('reflects a feature flag toggled at runtime without a restart', async () => {
		ApplicationConfig['deviceFlow.enabled'] = false;
		const before = await endpoint();
		expect(before).not.toHaveProperty('device_authorization_endpoint');
		expect(before.grant_types_supported).not.toContain(
			'urn:ietf:params:oauth:grant-type:device_code'
		);

		ApplicationConfig['deviceFlow.enabled'] = true;
		const after = await endpoint();
		expect(after).toHaveProperty('device_authorization_endpoint');
		expect(after.grant_types_supported).toContain(
			'urn:ietf:params:oauth:grant-type:device_code'
		);

		ApplicationConfig['deviceFlow.enabled'] = false;
		const reverted = await endpoint();
		expect(reverted).not.toHaveProperty('device_authorization_endpoint');
	});

	it('advertises client_credentials only while the feature flag is on', async () => {
		ApplicationConfig['clientCredentials.enabled'] = false;
		const before = await endpoint();
		expect(before.grant_types_supported).not.toContain('client_credentials');

		ApplicationConfig['clientCredentials.enabled'] = true;
		const after = await endpoint();
		expect(after.grant_types_supported).toContain('client_credentials');

		ApplicationConfig['clientCredentials.enabled'] = false;
		const reverted = await endpoint();
		expect(reverted.grant_types_supported).not.toContain('client_credentials');
	});

	it('reflects a collection value changed at runtime', async () => {
		ApplicationConfig.scopes = ['openid', 'offline_access', 'api:read'];
		const data = await endpoint();
		expect(data.scopes_supported).toContain('api:read');
	});
});
