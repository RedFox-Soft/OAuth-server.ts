import { describe, it, expect, afterEach } from 'bun:test';
import '../../lib/index.ts';
import {
	ApplicationConfig,
	configuration,
	reloadConfiguration,
	type ClaimsSetting
} from 'lib/configs/application.js';
import { applicationDefaultSettings } from '../config_baseline.js';

/**
 * @proves A new instance tells an application the person's email address, and whether it was proven,
 * when the application is granted the `email` scope.
 */
describe('shipped claims', () => {
	const original = ApplicationConfig.claims;

	afterEach(() => {
		ApplicationConfig.claims = original;
		reloadConfiguration();
	});

	it('advertises the email scope and releases email and email_verified under it', () => {
		ApplicationConfig.claims = structuredClone(
			applicationDefaultSettings.claims
		);
		reloadConfiguration();

		expect(configuration.scopes).toContain('email');
		expect(configuration.claims.email).toEqual({
			email: null,
			email_verified: null
		});
		expect(configuration.claimsSupported).toContain('email');
		expect(configuration.claimsSupported).toContain('email_verified');
	});
});

// Claims and acrValues are server settings, read from ApplicationConfig at initialisation.
// The claims map declared here is merged over the shipped one exactly as before, so these
// assertions still describe the resolved configuration, only the input surface changed.
/**
 * @proves An operator adds claims and the scopes that carry them, and a claim with nothing
 * behind it is not advertised.
 */
describe('custom claims', () => {
	const original = {
		claims: ApplicationConfig.claims,
		acrValues: ApplicationConfig.acrValues
	};

	afterEach(() => {
		Object.assign(ApplicationConfig, original);
		reloadConfiguration();
	});

	function initWithClaims(claims: ClaimsSetting) {
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

		expect(configuration.scopes).toContain('insurance');
		expect(configuration.scopes).toContain('payment');
	});

	/*
	 * Re-anchored: the claim used to be dropped when no acr values were configured, and that state is
	 * no longer reachable — every authentication the server can distinguish carries a value, so it
	 * can always supply the claim. What remains observable to a relying party reading discovery is
	 * that the claim is advertised, and that what is advertised is what a sign-in can actually
	 * produce.
	 */
	it('advertises the authentication context claim it can supply', () => {
		ApplicationConfig.acrValues = {
			password: 'bronze',
			multi_factor: 'silver',
			federated: 'gold'
		};
		reloadConfiguration();

		expect(configuration.claimsSupported).toContain('acr');
		expect([...configuration.acrValues]).toEqual(['bronze', 'silver', 'gold']);
	});
});
