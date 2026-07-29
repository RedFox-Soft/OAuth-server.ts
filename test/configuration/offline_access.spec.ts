import { describe, it, expect, afterEach } from 'bun:test';
import '../../lib/index.ts';
import {
	ApplicationConfig,
	configuration,
	reloadConfiguration
} from 'lib/configs/application.js';

// Scopes are a server setting now, so grant-type derivation reads them from ApplicationConfig.
describe('Provider declaring support for refresh_token grant type', () => {
	const originalScopes = ApplicationConfig.scopes;

	function initWithScopes(scopes: string[]) {
		ApplicationConfig.scopes = scopes;
		reloadConfiguration();
	}

	it('is enabled by default', () => {
		reloadConfiguration();
		expect(configuration.grantTypes).toContain('refresh_token');
	});

	it('isnt enabled when offline_access isnt amongst the scopes', () => {
		initWithScopes(['openid']);
		expect(configuration.grantTypes).not.toContain('refresh_token');
	});

	it('is enabled when offline_access isnt amongst the scopes', () => {
		initWithScopes(['openid', 'offline_access']);
		expect(configuration.grantTypes).toContain('refresh_token');
	});

	it('is enabled when the refreshToken.enabled flag is set', () => {
		ApplicationConfig['refreshToken.enabled'] = true;
		initWithScopes(['openid']);
		expect(configuration.grantTypes).toContain('refresh_token');
	});

	afterEach(() => {
		ApplicationConfig['refreshToken.enabled'] = false;
		ApplicationConfig.scopes = originalScopes;
	});
});
