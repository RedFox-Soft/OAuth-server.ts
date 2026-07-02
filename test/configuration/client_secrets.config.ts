import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'introspection.enabled': true,
	'revocation.enabled': true,
	'jwtIntrospection.enabled': true
};

export default {
	config
};
