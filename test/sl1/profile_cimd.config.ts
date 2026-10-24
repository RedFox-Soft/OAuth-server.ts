import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import * as profile from './profile.config.ts';

/* The IPSIE SL1 profile beside metadata-document support, and one application an administrator stored under a URL. */
export const PRE_REGISTERED = 'https://pre.example.com/oauth/client.json';

export const jwks = profile.jwks;

export const ApplicationConfig = {
	...profile.ApplicationConfig,
	'clientIdMetadataDocument.enabled': true
};

export const clients = [
	{
		clientId: PRE_REGISTERED,
		client_name: 'Pre-registered',
		bucketId: DEFAULT_BUCKET_ID,
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://pre.example.com/cb']
	}
];

export default profile.default;
