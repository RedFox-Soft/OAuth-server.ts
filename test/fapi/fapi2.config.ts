import { generateKeyPair, exportJWK } from 'jose';

import getConfig from '../default.config.js';

const config = getConfig();

export const keypair = await generateKeyPair('ES256');

export const ApplicationConfig = {
	'fapi.enabled': true,
	'requestObjects.enabled': true
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
