import getConfig from '../default.config.js';

const config = getConfig();

/*
 * SCIM on with static tokens (the credential the helpers hand a connection), and back-channel logout,
 * because a deprovisioning the guard admits must end access the way any other does.
 */
export const ApplicationConfig = {
	'scim.enabled': true,
	'scim.staticTokens': true,
	'backchannelLogout.enabled': true
};

export default {
	config
};
