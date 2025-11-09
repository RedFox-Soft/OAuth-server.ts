import { generateKeyPair, exportJWK } from 'jose';
import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

export const keypair = await generateKeyPair('ES256');

merge(config.features, {
	requestObjects: {
		enabled: true
	}
});

export const ApplicationConfig = {
	'fapi.enabled': true
};

export default {
	config,
	clients: [
		{
			clientId: 'client',
			token_endpoint_auth_method: 'private_key_jwt',
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			redirectUris: ['https://client.example.com/cb'],
			jwks: {
				keys: [await exportJWK(keypair.publicKey)]
			}
		}
	]
};
