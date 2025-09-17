import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

config.subjectTypes = ['pairwise', 'public'];
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
			grant_types: ['authorization_code'],
			response_types: ['none', 'code'],
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-pairwise',
			subject_type: 'pairwise',
			token_endpoint_auth_method: 'none',
			grant_types: ['authorization_code'],
			response_types: ['code'],
			redirectUris: ['https://client.example.com/cb']
		}
	]
};
