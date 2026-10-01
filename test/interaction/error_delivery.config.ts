import getConfig from '../default.config.js';

const config = getConfig();

/*
 * The JWT response modes are off by default, and a request naming one would be refused while it is
 * validated — so without this flag the JWT case would fail on the request, never reaching the delivery
 * it exists to prove.
 */
export const ApplicationConfig = {
	'resourceIndicators.enabled': true,
	'responseMode.jwt.enabled': true,
	'rpInitiatedLogout.enabled': false
};

export const REDIRECT_URI = 'https://client.example.com/cb';
/* The registration a case removes while a sign-in is in progress. */
export const SECOND_REDIRECT_URI = 'https://client.example.com/other';
export const AUDIENCE = 'https://api.example.com/mcp';

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		client_name: 'Test Client App',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: [REDIRECT_URI, SECOND_REDIRECT_URI]
	}
];

export default {
	config
};
