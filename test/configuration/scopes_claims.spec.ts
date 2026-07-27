import i from 'lib/helpers/weak_cache.js';
import { describe, it, expect, afterEach } from 'bun:test';
import provider from '../../lib/index.ts';
import { ApplicationConfig } from 'lib/configs/application.js';

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
		provider.init();
	});

	function initWithClaims(claims: Record<string, unknown>) {
		ApplicationConfig.claims = { ...original.claims, ...claims };
		provider.init();
	}

	it('allows for claims to be added under openid scope using array syntax', () => {
		initWithClaims({ openid: ['foo'] });

		expect(i(provider).configuration.claims.openid).toEqual({
			sub: null,
			foo: null
		});
	});

	it('allows for claims to be added under openid scope using object syntax', () => {
		initWithClaims({ openid: { foo: null } });

		expect(i(provider).configuration.claims.openid).toEqual({
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

		expect(i(provider).configuration.scopes).toContain('insurance', 'payment');
	});

	it('removes the acr claim if no acrs are configured', () => {
		ApplicationConfig.acrValues = [];
		provider.init();

		expect(i(provider).configuration.claimsSupported).not.toContain('acr');
	});
});
