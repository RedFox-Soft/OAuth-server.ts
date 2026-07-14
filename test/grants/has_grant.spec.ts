import { afterEach, describe, it, expect } from 'bun:test';

import { hasGrant } from 'lib/actions/grants/index.js';
import { ApplicationConfig } from 'lib/configs/application.js';

const DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code';
const CIBA = 'urn:openid:params:grant-type:ciba';

// Unit coverage for hasGrant's server-level feature-flag gating. Token dispatch
// (executeGrant) relies on this to hide grants whose feature is disabled, keeping
// it in lockstep with the discovery grant_types_supported derivation.
describe('hasGrant feature-flag gating', () => {
	afterEach(() => {
		ApplicationConfig['clientCredentials.enabled'] = false;
		ApplicationConfig['deviceFlow.enabled'] = false;
		ApplicationConfig['ciba.enabled'] = false;
	});

	it('gates client_credentials on clientCredentials.enabled', () => {
		ApplicationConfig['clientCredentials.enabled'] = false;
		expect(hasGrant('client_credentials')).toBe(false);

		ApplicationConfig['clientCredentials.enabled'] = true;
		expect(hasGrant('client_credentials')).toBe(true);
	});

	it('gates device_code on deviceFlow.enabled', () => {
		ApplicationConfig['deviceFlow.enabled'] = false;
		expect(hasGrant(DEVICE_CODE)).toBe(false);

		ApplicationConfig['deviceFlow.enabled'] = true;
		expect(hasGrant(DEVICE_CODE)).toBe(true);
	});

	it('gates ciba on ciba.enabled', () => {
		ApplicationConfig['ciba.enabled'] = false;
		expect(hasGrant(CIBA)).toBe(false);

		ApplicationConfig['ciba.enabled'] = true;
		expect(hasGrant(CIBA)).toBe(true);
	});

	it('leaves core grants ungated', () => {
		expect(hasGrant('authorization_code')).toBe(true);
		expect(hasGrant('refresh_token')).toBe(true);
	});

	it('returns false for unregistered grant types', () => {
		expect(hasGrant('does_not_exist')).toBe(false);
	});
});
