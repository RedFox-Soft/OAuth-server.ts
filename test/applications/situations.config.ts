import getConfig from '../default.config.js';

const config = getConfig();

/* Every grant a situation can choose is switched on, as on FoxAuth Cloud. */
export const ApplicationConfig = {
	'clientCredentials.enabled': true,
	'deviceFlow.enabled': true
};

export default {
	config
};
