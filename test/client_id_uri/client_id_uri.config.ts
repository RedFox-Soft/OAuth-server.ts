import merge from 'lodash/merge.js';

import nanoid from '../../lib/helpers/nanoid.ts';
import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'registration.enabled': true,
	'registrationManagement.enabled': true
};

merge(config.features, {
	registration: {
		idFactory() {
			return new URL(`https://repo.clients.com/path?id=${nanoid()}`).href;
		}
	}
});

export default {
	config
};
