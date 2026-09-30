import getConfig from '../default.config.js';

// No `jwks` here on purpose: the provider must fall back to the store-loaded root keys
// (seeded by test/preload.ts). This exercises the real store-loading path.
const config = getConfig();

export const ApplicationConfig = {
	'encryption.enabled': false
};

export default {
	config
};
