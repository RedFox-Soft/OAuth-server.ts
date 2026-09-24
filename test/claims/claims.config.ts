import getConfig from '../default.config.js';
import type { AddonImplementations } from 'lib/addon/types.js';

const config = getConfig();

export const ApplicationConfig = {
	'claimsParameter.enabled': true,
	acrValues: { password: '1', multi_factor: '2', federated: '3' }
};

export const addons: Partial<AddonImplementations> = {
	pairwiseIdentifier: (sub) => `${sub}-pairwise`
};
// This suite asserts scope/claims-parameter masking over a FULL OIDC profile;
// the spec seeds those claims onto the account via setSeedClaims(fullProfileClaims).

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['none', 'code'],
		redirectUris: ['https://client.example.com/cb']
	},
	{
		clientId: 'client-pairwise',
		subjectType: 'pairwise',
		token_endpoint_auth_method: 'none',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: ['https://client.example.com/cb']
	}
];

export default {
	config
};
