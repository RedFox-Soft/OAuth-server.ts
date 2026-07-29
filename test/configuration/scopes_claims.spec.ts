import { describe, it, expect, afterEach } from 'bun:test';
import '../../lib/index.ts';
import {
	ApplicationConfig,
	configuration,
	reloadConfiguration
} from 'lib/configs/application.js';

// Claims and acrValues are server settings, read from ApplicationConfig at initialisation.
// The claims map declared here is merged over the shipped one exactly as before, so these
// assertions still describe the resolved configuration, only the input surface changed.
describe('custom claims', () => {
	const original = {
		claims: ApplicationConfig.claims,
		acrValues: ApplicationConfig.acrValues
	};

	afterEach(() => {
		Object.assign(ApplicationConfig, original);
		reloadConfiguration();
	});

	function initWithClaims(claims: Record<string, unknown>) {
		ApplicationConfig.claims = { ...original.claims, ...claims };
		reloadConfiguration();
	}

	it('allows for claims to be added under openid scope using array syntax', () => {
		initWithClaims({ openid: ['foo'] });

		expect(configuration.claims.openid).toEqual({
			sub: null,
			foo: null
		});
	});

	it('allows for claims to be added under openid scope using object syntax', () => {
		initWithClaims({ openid: { foo: null } });

		expect(configuration.claims.openid).toEqual({
			sub: null,
			foo: null
		});
	});

	it('detects new scopes from claims definition', () => {
		initWithClaims({
			insurance: ['company_name', 'coverage'],
			payment: {
				preferred_method: null
			}
		});

		expect(configuration.scopes).toContain('insurance', 'payment');
	});

	it('removes the acr claim if no acrs are configured', () => {
		ApplicationConfig.acrValues = [];
		reloadConfiguration();

		expect(configuration.claimsSupported).not.toContain('acr');
	});
});
