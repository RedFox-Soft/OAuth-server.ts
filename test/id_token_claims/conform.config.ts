import getConfig from '../default.config.js';

const config = getConfig();

export const addons = {
	pairwiseIdentifier: () => 'pairwise-sub'
};
// Asserts scope-requested profile claims (gender, email, …); the spec seeds them
// onto the account via setSeedClaims(fullProfileClaims).

export const ApplicationConfig = {
	'claimsParameter.enabled': true,
	'registration.initialAccessToken': true,
	'registration.policies': {
		foo() {}
	}
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://client.example.com/cb']
	},
	{
		clientId: 'pairwise',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://client.example.com/cb'],
		subjectType: 'pairwise'
	}
];

export default {
	config
};
