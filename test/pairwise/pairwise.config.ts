import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'ciba.enabled': true,
	'deviceFlow.enabled': true
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		subjectType: 'pairwise',
		redirectUris: ['https://client.example.com/cb']
	},
	{
		clientId: 'client-static-with-sector',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		subjectType: 'pairwise',
		redirectUris: ['https://client.example.com/cb'],
		sector_identifier_uri: 'https://foobar.example.com/sector'
	}
];

export default {
	config
};
