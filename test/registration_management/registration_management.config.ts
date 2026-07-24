import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'registrationManagement.enabled': true,
	'registrationManagement.rotateRegistrationAccessToken': false,
	'registration.enabled': true
};

export const client = {
	clientId: 'client',
	clientSecret: 'secret',
	redirectUris: ['https://client.example.com/cb']
};

export default {
	config
};
