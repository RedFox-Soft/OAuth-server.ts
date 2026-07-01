import getConfig from '../default.config.js';

const config = getConfig();

// userinfo + jwtUserinfo enabled but encryption disabled: exercises a discovery key that
// depends on multiple features (userinfo_encryption_* requires all three).
export const ApplicationConfig = {
	'userinfo.enabled': true,
	'jwtUserinfo.enabled': true,
	'encryption.enabled': false
};

export default {
	config
};
