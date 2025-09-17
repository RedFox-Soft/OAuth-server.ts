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
		grant_types: ['authorization_code'],
		response_types: ['code'],
		redirectUris: ['https://client.example.com/cb']
	}
};
