import { exportJWK, generateKeyPair } from 'jose';

import getConfig from '../default.config.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { testSigningKeys } from '../jwks/fixtures.ts';

const config = getConfig();

/*
 * An instance running the IPSIE SL1 profile with everything it needs: DPoP, PKCE, encryption, registration behind an
 * initial access token, and a PS256 signer at the root. The clients are records as an instance would hold them —
 * written before the profile, not through registration — so the ones the profile refuses can exist at all.
 */
const rsa = testSigningKeys.find((key) => key.alg === 'RS256');
if (!rsa) throw new Error('the shared test keys hold no RSA key');

export const jwks = {
	keys: [...testSigningKeys, { ...rsa, alg: 'PS256', kid: `${rsa.kid}-ps256` }]
};

export const INITIAL_ACCESS_TOKEN = 'sl1-initial-access-token';

export const ApplicationConfig = {
	'ipsieSl1.enabled': true,
	'dpop.enabled': true,
	'pkce.required': true,
	'encryption.enabled': true,
	'registration.enabled': true,
	'registration.initialAccessToken': INITIAL_ACCESS_TOKEN,
	'par.enabled': true,
	'clientCredentials.enabled': true,
	'deviceFlow.enabled': true,
	'requestObjects.enabled': true,
	'mTLS.enabled': true,
	'mTLS.certificateBoundAccessTokens': true
};

/* The key a private_key_jwt client signs its assertions with, in an algorithm the profile accepts. */
export const assertionKey = await generateKeyPair('PS256', {
	extractable: true
});

const web = {
	bucketId: DEFAULT_BUCKET_ID,
	grantTypes: ['authorization_code', 'refresh_token'],
	responseTypes: ['code'],
	redirectUris: ['https://sl1.example.com/cb']
};

export const clients = [
	{ ...web, clientId: 'sl1-web', clientSecret: 'sl1-web-secret' },
	{ ...web, clientId: 'sl1-spa', token_endpoint_auth_method: 'none' },
	{
		...web,
		clientId: 'sl1-native',
		applicationType: 'native',
		token_endpoint_auth_method: 'none',
		redirectUris: ['com.example.sl1:/callback']
	},
	{
		...web,
		clientId: 'sl1-loopback',
		applicationType: 'native',
		token_endpoint_auth_method: 'none',
		redirectUris: ['http://127.0.0.1/cb'],
		post_logout_redirect_uris: ['http://127.0.0.1/bye']
	},
	{
		...web,
		clientId: 'sl1-none',
		clientSecret: 'sl1-none-secret',
		responseTypes: ['code', 'none']
	},
	// RS256 as a console save writes it: the default, stored.
	{
		...web,
		clientId: 'sl1-rs256',
		clientSecret: 'sl1-rs256-secret',
		id_token_signed_response_alg: 'RS256'
	},
	{
		...web,
		clientId: 'sl1-hs256',
		clientSecret: 'a-shared-secret-long-enough-for-hs256-signing',
		id_token_signed_response_alg: 'HS256'
	},
	{
		...web,
		clientId: 'sl1-hmac',
		clientSecret: 'a-shared-secret-long-enough-for-hs256-signing',
		token_endpoint_auth_method: 'client_secret_jwt'
	},
	{
		...web,
		clientId: 'sl1-pkjwt',
		responseTypes: [],
		redirectUris: [],
		token_endpoint_auth_method: 'private_key_jwt',
		token_endpoint_auth_signing_alg: 'PS256',
		grantTypes: ['client_credentials'],
		jwks: { keys: [await exportJWK(assertionKey.publicKey)] }
	},
	{
		...web,
		clientId: 'sl1-machine',
		responseTypes: [],
		redirectUris: [],
		clientSecret: 'sl1-machine-secret',
		grantTypes: ['client_credentials']
	},
	{
		...web,
		clientId: 'sl1-mtls',
		responseTypes: [],
		redirectUris: [],
		clientSecret: 'sl1-mtls-secret',
		grantTypes: ['client_credentials'],
		tls_client_certificate_bound_access_tokens: true
	}
];

export default {
	config
};
