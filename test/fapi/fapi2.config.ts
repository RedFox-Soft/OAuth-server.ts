import { generateKeyPair, exportJWK } from 'jose';

import getConfig from '../default.config.js';

const config = getConfig();

export const keypair = await generateKeyPair('ES256');

export const ApplicationConfig = {
	'fapi.enabled': true,
	'requestObjects.enabled': true,
	// This spec drives POST /par. It used to pass with PAR switched off, because every endpoint
	// answered regardless of its flag; now that a disabled capability is unreachable, the flag has
	// to be declared. FAPI 2.0 mandates PAR anyway, so the omission was always wrong.
	'par.enabled': true
};

export const clients = [
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
];

export default {
	config
};
