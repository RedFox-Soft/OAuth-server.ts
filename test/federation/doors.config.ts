import getConfig from '../default.config.js';

const config = getConfig();

/*
 * A separate config from `signin` so this suite can hold clients whose buckets are federated-only without
 * changing what the sign-in suite exercises.
 */
export const ApplicationConfig = {
	'federation.enabled': true
};

export const clients = [
	{
		clientId: 'doors-federated-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/doors-federated/callback']
	},
	{
		clientId: 'doors-password-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/doors-password/callback']
	}
];

export default {
	config
};
