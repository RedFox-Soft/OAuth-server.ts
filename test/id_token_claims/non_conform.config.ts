import cloneDeep from 'lodash/cloneDeep.js';

import config from './conform.config.js';

const setup = cloneDeep(config);

// conformIdTokenClaims now lives on ApplicationConfig. Only that flag is exported: the base
// config's own ApplicationConfig flags were never inherited here (the default export is all
// that was cloned), and spreading them in now would change what this spec exercises.
export const ApplicationConfig = {
	conformIdTokenClaims: false
};

// Clients are seeded from the `clients` named export; inherit the base set.
export { clients } from './conform.config.js';

export default setup;
