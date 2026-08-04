import getConfig from '../default.config.js';

const config = getConfig();

// The pages reached over HTTP in csp.spec.ts: the auto-submit response mode, the device user-code
// page and the logout confirmation. Everything else is exercised through its renderer, which is the
// only way an HTML response can be built at all (see the drift guard in the spec).
export const ApplicationConfig = {
	'deviceFlow.enabled': true,
	'rpInitiatedLogout.enabled': true
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com/cb']
	}
];

export default {
	config
};
