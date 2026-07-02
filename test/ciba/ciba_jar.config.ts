import cloneDeep from 'lodash/cloneDeep.js';

import config, {
	ApplicationConfig as CibaApplicationConfig
} from './ciba.config.js';

export const ApplicationConfig = {
	...CibaApplicationConfig,
	'requestObjects.enabled': true
};

export default cloneDeep(config);
