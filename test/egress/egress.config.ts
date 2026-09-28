import getConfig from '../default.config.js';

const config = getConfig();

/*
 * The capabilities whose client metadata names an address this server will contact: a key set, a
 * sector document and a back-channel logout endpoint. Switched on so the attributes are recognised at
 * registration, which is where a caller supplies them.
 */
export const ApplicationConfig = {
	'backchannelLogout.enabled': true
};

export default {
	config
};
