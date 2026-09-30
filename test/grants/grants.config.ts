import getConfig from '../default.config.js';

const config = getConfig();

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		redirectUris: ['https://client.example.com/cb']
	},
	// Kept apart from `client`, which the parity guard relies on being registered for
	// authorization_code alone: a grant the server supports but the client lacks is then answered
	// unauthorized_client, which is how the guard tells "supported" from "unsupported".
	{
		clientId: 'offline',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://offline.example.com/cb']
	}
];

export default {
	config
};
