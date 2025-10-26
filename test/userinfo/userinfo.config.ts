import getConfig from '../default.config.js';

const config = getConfig();

config.findAccount = (ctx, id) => {
	if (id === 'notfound') return undefined;
	return {
		accountId: id,
		claims() {
			return { sub: id, email: 'foo@example.com', email_verified: false };
		}
	};
};

config.claims = {
	email: ['email', 'email_verified']
};

export default {
	config,
	client: {
		clientId: 'client',
		clientSecret: 'secret',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com/cb']
	}
};
