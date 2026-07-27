import cloneDeep from 'lodash/cloneDeep.js';

import config, { ApplicationConfig as base } from './device_code.config.js';

const setup = cloneDeep(config);

// conformIdTokenClaims=false puts scope-derived profile claims (given_name, …)
// into the id_token; the spec seeds them via setSeedClaims(fullProfileClaims).
//
// The base feature flags (deviceFlow.enabled, etc.) are spread in because the harness reads
// one ApplicationConfig named export per config module — without them the flags revert to
// defaults and the device_code grant would be gated off at the token endpoint.
export const ApplicationConfig = {
	...base,
	conformIdTokenClaims: false
};

// Clients are seeded from the `clients` named export; inherit the base set.
export { clients } from './device_code.config.js';

export default setup;
