import merge from 'lodash/merge.js';

import getConfig from '../default.config.js';
import { testSigningKeys } from '../jwks/fixtures.js';

const config = getConfig();

config.extraTokenClaims = () => ({ foo: 'bar' });
merge(config.features, {
	registration: {
		initialAccessToken: true,
		policies: {
			foo() {}
		}
	}
});
config.pairwiseIdentifier = () => 'pairwise-sub';

// Provide an additional, algorithm-unlocked RSA signing key so the JWT format tests can
// exercise PS256 (the default RSA key is pinned to RS256). Scoped to this test's provider
// via configuration.jwks; the default keys are retained so RS256 resolution is unchanged.
const baseKeys = testSigningKeys;
const { alg: _alg, use: _use, kid: _kid, ...rsaMaterial } = baseKeys[0];
config.jwks = {
	keys: [...baseKeys, { ...rsaMaterial, kid: 'ps256-test-key' }]
};

export default {
	config,
	clients: [
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
	]
};
