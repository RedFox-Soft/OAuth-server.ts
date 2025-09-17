import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

config.subjectTypes = ['public', 'pairwise'];
merge(config.features, {
	encryption: { enabled: true },
	clientCredentials: { enabled: true }
});

export const ApplicationConfig = {
	'introspection.enabled': true
};

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-pairwise',
			clientSecret: 'secret',
			subject_type: 'pairwise',
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-introspection',
			clientSecret: 'secret',
			redirectUris: [],
			response_types: [],
			grant_types: []
		},
		{
			clientId: 'client-none',
			token_endpoint_auth_method: 'none',
			redirectUris: [],
			grant_types: [],
			response_types: []
		}
	]
};
