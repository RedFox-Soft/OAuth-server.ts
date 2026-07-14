import cloneDeep from 'lodash/cloneDeep.js';

import config, { ApplicationConfig } from './device_code.config.js';

const setup = cloneDeep(config);

setup.config.conformIdTokenClaims = false;

// Re-export the base feature flags (deviceFlow.enabled, etc.) — the harness reads the
// ApplicationConfig named export per config module, so without this the flags revert to
// defaults and the device_code grant would be gated off at the token endpoint.
export { ApplicationConfig };

export default setup;
