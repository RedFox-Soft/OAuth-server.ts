import cloneDeep from 'lodash/cloneDeep.js';

import config, {
	ApplicationConfig as CibaApplicationConfig
} from './ciba.config.js';

export const ApplicationConfig = {
	...CibaApplicationConfig,
	'requestObjects.enabled': true
};

// Clients are seeded from the `clients` named export; inherit the base ciba set
// (the harness reads this export per config module, not the default export).
export { clients } from './ciba.config.js';

export default cloneDeep(config);
