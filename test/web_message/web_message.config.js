import getConfig from '../default.config.js';

const config = getConfig();
config.features.webMessageResponseMode = { enabled: true };

export default {
	config,
	client: {
		client_id: 'client',
		grant_types: ['authorization_code'],
		response_types: ['code'],
		redirect_uris: ['https://client.example.com'],
		token_endpoint_auth_method: 'none'
	}
};
