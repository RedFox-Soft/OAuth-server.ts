import cloneDeep from 'lodash/cloneDeep.js';

import config from './conform.config.js';

const setup = cloneDeep(config);

setup.config.conformIdTokenClaims = false;

// Clients are seeded from the `clients` named export; inherit the base set.
export { clients } from './conform.config.js';

export default setup;
