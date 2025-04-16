import getConfig from '../default.config.js';

const config = getConfig();

export default {
	config,
	client: {
		client_id: 'client',
		client_secret: 'secret',
		token_endpoint_auth_method: 'none',
		grant_types: ['authorization_code'],
		response_types: ['code'],
		redirect_uris: ['https://client.example.com/cb']
	}
};
