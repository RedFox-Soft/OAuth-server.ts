import getConfig from '../default.config.js';

const config = getConfig();

/*
 * The error store is on so that "an undeliverable report leaves no error-store record" is a claim about a
 * store that would have recorded it. Client credentials is on because it is the shortest way to make the
 * token endpoint issue tokens a case can count.
 */
export const ApplicationConfig = {
	'errorStore.enabled': true,
	'clientCredentials.enabled': true,
	scopes: ['api:read']
};

export const client = {
	clientId: 'tele-machine',
	clientSecret: 'tele-secret',
	grantTypes: ['client_credentials'],
	responseTypes: [],
	redirectUris: [],
	scope: 'api:read'
};

export default {
	config
};
