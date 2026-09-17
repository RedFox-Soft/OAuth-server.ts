import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Its own config rather than borrowing `signin`'s: the buckets here hold a provider at a *recognised*
 * issuer, and the sign-in suite's providers deliberately sit at a stub origin nobody recognises. Sharing
 * one config would mean either changing what that suite exercises or seeding both kinds into one bucket,
 * and the second is the thing these cases are about telling apart.
 */
export const ApplicationConfig = {
	'federation.enabled': true
};

export const clients = [
	{
		clientId: 'brand-google-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/brand-google/callback']
	},
	{
		clientId: 'brand-plain-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/brand-plain/callback']
	},
	{
		clientId: 'brand-none-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/brand-none/callback']
	}
];

export default {
	config
};
