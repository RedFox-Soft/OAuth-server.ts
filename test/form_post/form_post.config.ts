import getConfig from '../default.config.js';

const config = getConfig();

export const client = {
	clientId: 'client',
	clientSecret: 'secret',
	grantTypes: ['authorization_code'],
	responseTypes: ['code'],
	redirectUris: [
		'https://client.example.com/cb',
		'https://client.example.com/cb%22%3Cscript%3Ealert(0)%3C/script%3E%3Cx=%22'
	]
};

export default {
	config
};
