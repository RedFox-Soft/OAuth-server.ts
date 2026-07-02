import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'encryption.enabled': true,
	'introspection.enabled': true,
	'jwtIntrospection.enabled': true
};

export default {
	config
};
