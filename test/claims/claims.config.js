import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

config.subjectTypes = ['pairwise', 'public'];
merge(config.features, { claimsParameter: { enabled: true } });
config.acrValues = ['0', '1', '2'];
config.pairwiseIdentifier = (ctx, sub) => `${sub}-pairwise`;

export default {
	config,
	clients: [
		{
			client_id: 'client',
			client_secret: 'secret',
			token_endpoint_auth_method: 'none',
			grant_types: ['implicit', 'authorization_code'],
			response_types: ['none', 'code'],
			redirect_uris: ['https://client.example.com/cb']
		},
		{
			client_id: 'client-pairwise',
			subject_type: 'pairwise',
			token_endpoint_auth_method: 'none',
			grant_types: ['authorization_code'],
			response_types: ['code'],
			redirect_uris: ['https://client.example.com/cb']
		}
	]
};
