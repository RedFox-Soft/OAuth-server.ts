import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';

import cloneDeep from 'lodash/cloneDeep.js';
import merge from 'lodash/merge.js';

import key from '../client.sig.key.js';
import getConfig from '../default.config.js';

const mtlsKeys = JSON.parse(
	readFileSync('test/jwks/jwks.json', {
		encoding: 'utf-8'
	})
);

const config = getConfig();

const clientKey = {
	e: key.e,
	n: key.n,
	kid: key.kid,
	kty: key.kty,
	use: key.use
};
const rsaKeys = cloneDeep(mtlsKeys);
rsaKeys.keys.splice(0, 1);

config.clientAuthMethods = [
	'none',
	'client_secret_basic',
	'client_secret_post',
	'private_key_jwt',
	'client_secret_jwt',
	'tls_client_auth',
	'self_signed_tls_client_auth'
];
merge(config.features, {
	introspection: { enabled: true },
	mTLS: {
		enabled: true,
		selfSignedTlsClientAuth: true,
		tlsClientAuth: true,
		getCertificate(ctx) {
			try {
				return new X509Certificate(
					Buffer.from(ctx.get('x-ssl-client-cert'), 'base64')
				);
			} catch (e) {
				return undefined;
			}
		},
		certificateAuthorized(ctx) {
			return ctx.get('x-ssl-client-verify') === 'SUCCESS';
		},
		certificateSubjectMatches(ctx, property, expected) {
			return (
				property === 'tls_client_auth_san_dns' &&
				ctx.get('x-ssl-client-san-dns') === expected
			);
		}
	}
});

export default {
	config,
	clients: [
		{
			token_endpoint_auth_method: 'none',
			clientId: 'client-none',
			clientSecret: 'secret',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: []
		},
		{
			token_endpoint_auth_method: 'client_secret_basic',
			clientId: 'client-basic',
			clientSecret: 'secret',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: []
		},
		{
			token_endpoint_auth_method: 'client_secret_basic',
			clientId: 'an:identifier',
			clientSecret: 'some secure & non-standard secret',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: []
		},
		{
			token_endpoint_auth_method: 'client_secret_post',
			clientId: 'client-post',
			clientSecret: 'secret',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: []
		},
		{
			token_endpoint_auth_method: 'client_secret_jwt',
			clientId: 'client-jwt-secret',
			clientSecret: 'secret',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: []
		},
		{
			clientId: 'client-jwt-key',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: [],
			token_endpoint_auth_method: 'private_key_jwt',
			jwks: {
				keys: [clientKey]
			}
		},
		{
			clientId: 'client-pki-mtls',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: [],
			token_endpoint_auth_method: 'tls_client_auth',
			tls_client_auth_san_dns: 'rp.example.com'
		},
		{
			clientId: 'client-self-signed-mtls',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: [],
			token_endpoint_auth_method: 'self_signed_tls_client_auth',
			jwks: mtlsKeys
		},
		{
			clientId: 'client-self-signed-mtls-rsa',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: [],
			token_endpoint_auth_method: 'self_signed_tls_client_auth',
			jwks: rsaKeys
		},
		{
			clientId: 'client-self-signed-mtls-jwks_uri',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: [],
			token_endpoint_auth_method: 'self_signed_tls_client_auth',
			jwks_uri: 'https://client.example.com/jwks'
		},
		{
			clientId: 'secret-expired-basic',
			clientSecret: 'secret',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: [],
			client_secret_expires_at: 1
		},
		{
			clientId: 'secret-expired-jwt',
			clientSecret: 'secret',
			token_endpoint_auth_method: 'client_secret_jwt',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: [],
			client_secret_expires_at: 1
		},
		// Appendix B
		{
			token_endpoint_auth_method: 'client_secret_basic',
			clientId: ' %&+',
			clientSecret: ' %&+',
			grantTypes: ['foo'],
			responseTypes: [],
			redirectUris: []
		}
	]
};
