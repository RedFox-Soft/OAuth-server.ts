import getConfig from '../default.config.js';

const config = getConfig();

/*
 * `claimsParameter.enabled` is what makes an *essential* context request expressible at all: with it
 * off, `params.claims` never reaches `oidc.claims`, no requirement can be stated, and OIDC Core
 * §5.5.1.1's MUST does not apply ("and the implementation supports the claims parameter"). It ships
 * off, so the whole essential path is reachable only here and in a deployment that turns it on.
 *
 * The context values are renamed away from the shipped defaults on purpose: an operator naming their
 * own vocabulary is the supported case, and pinning the shipped strings in a fixture would make
 * these cases fail on a rename that broke nothing.
 */
export const ApplicationConfig = {
	'claimsParameter.enabled': true,
	acrValues: {
		password: 'urn:example:acr:pwd',
		multi_factor: 'urn:example:acr:mfa',
		federated: 'urn:example:acr:federated'
	}
};

/*
 * One client per bucket state, so no spec has to mutate a bucket another spec is using — the
 * arrangement test/totp/totp.config.ts settled on for the same reason. `acr-mfa-app` belongs to a
 * bucket that demands a second factor, which is the only way a sign-in here reaches the
 * multi-factor context.
 */
export const clients = [
	{
		clientId: 'acr-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/acr/callback'],
		'consent.require': false
	},
	{
		clientId: 'acr-mfa-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/acr-mfa/callback'],
		'consent.require': false
	},
	{
		clientId: 'acr-defaults-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/acr-defaults/callback'],
		'consent.require': false,
		default_acr_values: ['urn:example:acr:mfa']
	}
];

export default {
	config
};
