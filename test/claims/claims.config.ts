import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, { claimsParameter: { enabled: true } });
config.acrValues = ['0', '1', '2'];
config.pairwiseIdentifier = (sub) => `${sub}-pairwise`;

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			token_endpoint_auth_method: 'none',
			grantTypes: ['authorization_code'],
			responseTypes: ['none', 'code'],
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-pairwise',
			subjectType: 'pairwise',
			token_endpoint_auth_method: 'none',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: ['https://client.example.com/cb']
		}
	]
};
