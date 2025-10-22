import getConfig from '../default.config.js';

const config = getConfig();

config.features.ciba = { enabled: true };
config.features.deviceFlow = { enabled: true };

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			grant_types: ['authorization_code'],
			responseTypes: ['code'],
			subjectType: 'pairwise',
			redirectUris: ['https://client.example.com/cb']
		},
		{
			clientId: 'client-static-with-sector',
			clientSecret: 'secret',
			grant_types: ['authorization_code'],
			responseTypes: ['code'],
			subjectType: 'pairwise',
			redirectUris: ['https://client.example.com/cb'],
			sector_identifier_uri: 'https://foobar.example.com/sector'
		}
	]
};
