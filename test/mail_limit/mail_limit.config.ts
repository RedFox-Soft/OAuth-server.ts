import getConfig from '../default.config.js';

const config = getConfig();

/* A limit of three, so "past the limit" is the fourth request rather than the eleventh. */
export const ApplicationConfig = {
	'mail.requestsPerCallerPerHour': 3
};

export const clients = [
	{
		clientId: 'mail-limit-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/mail-limit/callback']
	}
];

export default {
	config
};
