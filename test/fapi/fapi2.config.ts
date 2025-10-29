import { strict as assert } from 'node:assert';

import { generateKeyPair, exportJWK } from 'jose';
import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';

const config = getConfig();

export const keypair = await generateKeyPair('ES256');

merge(config.features, {
	fapi: {
		enabled: true,
		profile(ctx, client) {
			assert(ctx, 'ctx not provided in fapi.profile');
			assert(client, 'client not provided in fapi.profile');
			return '2.0';
		}
	},
	requestObjects: {
		enabled: true
	}
});

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
