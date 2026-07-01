import getConfig from '../default.config.js';

const config = getConfig();

// All optional features disabled, including the two that default to on (userinfo,
// rpInitiatedLogout), so the discovery document is reduced to its always-present keys.
export const ApplicationConfig = {
	'userinfo.enabled': false,
	'rpInitiatedLogout.enabled': false
};

export default {
	config
};
