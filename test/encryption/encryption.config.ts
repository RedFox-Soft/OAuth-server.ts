import { generateKeyPair, exportJWK } from 'jose';
import merge from 'lodash/merge.js';
import pull from 'lodash/pull.js';

import getConfig from '../default.config.js';

const config = getConfig();

merge(config.features, {
	requestObjects: { enabled: true },
	encryption: { enabled: true },
	introspection: { enabled: true },
	jwtIntrospection: { enabled: true },
	jwtUserinfo: { enabled: true }
});

// pull(config.enabledJWA.requestObjectEncryptionAlgValues, 'RSA-OAEP-512');
pull(config.enabledJWA.requestObjectEncryptionEncValues, 'A192CBC-HS384');

export const keypair = await generateKeyPair('RSA-OAEP');

export const ApplicationConfig = {
	'par.enabled': true
};

export default {
	config,
	clients: [
		{
			clientId: 'client',
			clientSecret: 'secret',
			redirectUris: ['https://client.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			jwks: { keys: [await exportJWK(keypair.publicKey)] },
			id_token_encrypted_response_alg: 'RSA-OAEP',
			// id_token_encrypted_response_enc: 'A128CBC-HS256',
			request_object_encryption_alg: 'RSA-OAEP',
			// request_object_encryption_enc: 'A128CBC-HS256',
			userinfo_signed_response_alg: 'RS256',
			userinfo_encrypted_response_alg: 'RSA-OAEP'
			// userinfo_encrypted_response_enc: 'A128CBC-HS256',
		},
		{
			clientId: 'clientSymmetric',
			clientSecret: 'secret',
			redirectUris: ['https://client.example.com/cb'],
			token_endpoint_auth_method: 'none',
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			id_token_encrypted_response_alg: 'A128KW'
		},
		{
			clientId: 'clientSymmetric-expired',
			clientSecret: 'secret',
			redirectUris: ['https://client.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			client_secret_expires_at: 1,
			id_token_encrypted_response_alg: 'A128KW'
		},
		{
			clientId: 'clientSymmetric-dir',
			clientSecret: 'secret',
			redirectUris: ['https://client.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			id_token_encrypted_response_alg: 'dir'
		},
		{
			clientId: 'clientRequestObjectSigningAlg',
			clientSecret: 'secret',
			redirectUris: ['https://client.example.com/cb'],
			responseTypes: ['code'],
			grantTypes: ['authorization_code'],
			request_object_signing_alg: 'HS256'
		}
	]
};
