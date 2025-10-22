import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

config.extraTokenClaims = () => ({ foo: 'bar' });
merge(config.features, {
	registration: {
		initialAccessToken: true,
		policies: {
			foo() {}
		}
	}
});
config.pairwiseIdentifier = () => 'pairwise-sub';

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'pairwise',
			clientSecret: 'secret',
			redirectUris: ['https://client.example.com/cb'],
			subjectType: 'pairwise'
		}
	]
};
