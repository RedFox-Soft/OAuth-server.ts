import getConfig from '../default.config.js';

const config = getConfig();

// findAccount is the built-in DB-backed resolver (no longer a config option).
// login() seeds a user with an email, so `openid email` requests resolve email
// claims; the 'notfound' test uses an unseeded subject, which resolves to nothing.
export const ApplicationConfig = {
	claims: {
		email: ['email', 'email_verified']
	}
};

export const client = {
	clientId: 'client',
	clientSecret: 'secret',
	token_endpoint_auth_method: 'none',
	grantTypes: ['authorization_code'],
	responseTypes: ['code'],
	redirectUris: ['https://client.example.com/cb']
};

export default {
	config
};
