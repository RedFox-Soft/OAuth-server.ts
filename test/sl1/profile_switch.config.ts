import getConfig from '../default.config.js';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { testSigningKeys } from '../jwks/fixtures.ts';

const config = getConfig();

/*
 * An instance with the IPSIE SL1 profile off, as an operator meets it before switching: DPoP and encryption off, and
 * two applications in the default project the profile would refuse. The root issuer holds a PS256 signer, so the one
 * issuer prerequisite a case wants unmet is a project it creates itself.
 */
const rsa = testSigningKeys.find((key) => key.alg === 'RS256');
if (!rsa) throw new Error('the shared test keys hold no RSA key');

export const jwks = {
	keys: [...testSigningKeys, { ...rsa, alg: 'PS256', kid: `${rsa.kid}-ps256` }]
};

export const ApplicationConfig = {
	'deviceFlow.enabled': true
};

export const clients = [
	{
		clientId: 'sl1-loopback',
		client_name: 'Loopback CLI',
		bucketId: DEFAULT_BUCKET_ID,
		applicationType: 'native',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['http://127.0.0.1/cb']
	},
	{
		clientId: 'sl1-hmac',
		client_name: 'Shared-secret JWT app',
		bucketId: DEFAULT_BUCKET_ID,
		clientSecret: 'a-shared-secret-long-enough-for-hs256-signing',
		token_endpoint_auth_method: 'client_secret_jwt',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://hmac.example.com/cb']
	}
];

export default {
	config
};
