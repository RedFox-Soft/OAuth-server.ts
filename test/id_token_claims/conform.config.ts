import getConfig from '../default.config.js';

const config = getConfig();

config.extraTokenClaims = () => ({ foo: 'bar' });
config.pairwiseIdentifier = () => 'pairwise-sub';

export const ApplicationConfig = {
	'claimsParameter.enabled': true,
	'registration.initialAccessToken': true,
	'registration.policies': {
		foo() {}
	}
};

export default {
	config,
	clients: [
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
	]
};
