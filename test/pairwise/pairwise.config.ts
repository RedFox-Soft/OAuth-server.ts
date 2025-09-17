import getConfig from '../default.config.js';

const config = getConfig();

config.subjectTypes = ['public', 'pairwise'];
config.features.ciba = { enabled: true };
config.features.deviceFlow = { enabled: true };

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			grant_types: ['authorization_code'],
			response_types: ['code'],
			subject_type: 'pairwise',
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-static-with-sector',
			clientSecret: 'secret',
			grant_types: ['authorization_code'],
			response_types: ['code'],
			subject_type: 'pairwise',
			redirectUris: ['https://client.example.com/cb'],
			sector_identifier_uri: 'https://foobar.example.com/sector'
		}
	]
};
