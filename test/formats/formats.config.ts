import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';
import { testSigningKeys } from '../jwks/fixtures.js';

const config = getConfig();

merge(config.features, {
	registration: {
		initialAccessToken: true,
		policies: {
			foo() {}
		}
	}
});
export const addons = {
	pairwiseIdentifier: () => 'pairwise-sub'
};

// Provide an additional PS256 RSA signing key so the JWT format tests can exercise PS256 (the
// default RSA key is pinned to RS256). Seeded into the jwksStore for this spec by the harness;
// the default keys are retained so RS256 resolution is unchanged. Every key in the store must
// declare its `alg`, so this one is pinned to PS256 rather than left unspecified.
const baseKeys = testSigningKeys;
const { use: _use, kid: _kid, ...rsaMaterial } = baseKeys[0];
export const jwks = {
	keys: [...baseKeys, { ...rsaMaterial, alg: 'PS256', kid: 'ps256-test-key' }]
};

export const clients = [
	{
		clientId: 'client',
		clientSecret: 'secret',
		redirectUris: ['https://client.example.com/cb']
	},
	{
		clientId: 'pairwise',
		clientSecret: 'secret',
		redirectUris: ['https://client.example.com/cb'],
		subjectType: 'pairwise'
	}
];

export default {
	config
};
