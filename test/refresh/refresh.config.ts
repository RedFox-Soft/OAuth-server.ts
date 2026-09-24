import getConfig from '../default.config.js';
import type { AddonImplementations } from 'lib/addon/types.js';

const config = getConfig();

export const addons: Partial<AddonImplementations> = {
	rotateRefreshToken: () => false
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com/cb']
	},
	{
		clientId: 'client2',
		clientSecret: 'secret',
		grantTypes: ['authorization_code', 'refresh_token'],
		redirectUris: ['https://client.example.com/cb']
	}
];

export default {
	config
};
