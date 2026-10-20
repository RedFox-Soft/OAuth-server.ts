import getConfig from '../default.config.js';

const config = getConfig();

/*
 * One client per project state, so no case changes a project another case relies on: the projects are
 * seeded in the spec's beforeAll, because their sign-up and password settings are what the cases differ by.
 */
export const clients = [
	{
		clientId: 'create-open-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/create-open/callback'],
		// So a sign-in ends the authorization, and the case can read the code it returns.
		'consent.require': false
	},
	{
		clientId: 'create-closed-app',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://e.ly/create-closed/callback']
	}
];

export default {
	config
};
