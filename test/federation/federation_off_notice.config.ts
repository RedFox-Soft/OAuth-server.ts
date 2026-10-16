import getConfig from '../default.config.js';

/*
 * Federation off, the instance default: a project can hold enabled providers whose buttons appear nowhere,
 * which is what the administrator has to be told. Cases that need it on switch it for themselves.
 */
export const ApplicationConfig = {
	'federation.enabled': false
};

export default { config: getConfig() };
