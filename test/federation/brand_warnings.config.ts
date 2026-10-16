import getConfig from '../default.config.js';

/* Federation on, so the only reason a warning appears is how the providers are set up. */
export const ApplicationConfig = {
	'federation.enabled': true
};

export default { config: getConfig() };
