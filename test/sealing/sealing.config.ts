import getConfig from '../default.config.js';

const config = getConfig();

/*
 * Client credentials is on because a confidential client authenticating with its secret is the shortest
 * observable proof that a sealed secret opens again, and the clearest one that an unreadable one does not.
 */
export const ApplicationConfig = {
	'clientCredentials.enabled': true,
	scopes: ['api:read']
};

export const client = {
	clientId: 'sealing-machine',
	clientSecret: 'sealing-secret-sealing-secret-sealing-secret',
	grantTypes: ['client_credentials'],
	responseTypes: [],
	redirectUris: [],
	scope: 'api:read'
};

export default {
	config
};
