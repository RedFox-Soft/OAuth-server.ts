import { describe, it, beforeAll, afterAll } from 'bun:test';
import { expect } from 'chai';

import bootstrap, { agent } from '../test_helper.js';
import { ApplicationConfig } from '../../lib/configs/application.js';

const endpoint = () => agent['.well-known']['openid-configuration'].get();

describe('discovery runtime mutability', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url)();
	});

	afterAll(() => {
		ApplicationConfig['deviceFlow.enabled'] = false;
		ApplicationConfig.scopes = ['openid', 'offline_access'];
	});

	it('reflects a feature flag toggled at runtime without a restart', async () => {
		ApplicationConfig['deviceFlow.enabled'] = false;
		const before = (await endpoint()).data as Record<string, unknown>;
		expect(before).not.to.have.property('device_authorization_endpoint');
		expect(before.grant_types_supported).not.to.include(
			'urn:ietf:params:oauth:grant-type:device_code'
		);

		ApplicationConfig['deviceFlow.enabled'] = true;
		const after = (await endpoint()).data as Record<string, unknown>;
		expect(after).to.have.property('device_authorization_endpoint');
		expect(after.grant_types_supported).to.include(
			'urn:ietf:params:oauth:grant-type:device_code'
		);

		ApplicationConfig['deviceFlow.enabled'] = false;
		const reverted = (await endpoint()).data as Record<string, unknown>;
		expect(reverted).not.to.have.property('device_authorization_endpoint');
	});

	it('reflects a collection value changed at runtime', async () => {
		ApplicationConfig.scopes = ['openid', 'offline_access', 'api:read'];
		const { data } = await endpoint();
		expect((data as Record<string, unknown>).scopes_supported).to.include(
			'api:read'
		);
	});
});
