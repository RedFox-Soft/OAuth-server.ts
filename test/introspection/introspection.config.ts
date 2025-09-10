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
			client_secret: 'secret',
			redirect_uris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-pairwise',
			client_secret: 'secret',
			subject_type: 'pairwise',
			redirect_uris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-introspection',
			client_secret: 'secret',
			redirect_uris: [],
			response_types: [],
			grant_types: []
		},
		{
			clientId: 'client-none',
			token_endpoint_auth_method: 'none',
			redirect_uris: [],
			grant_types: [],
			response_types: []
		}
	]
};
