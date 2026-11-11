import getConfig from '../default.config.js';

/*
 * A path behind the proxy that asks for a code, reached through an outside sign-in provider (specs/128). The same
 * settings as the area's own config, with federation on so the project's provider can sign people in.
 */
export const ApplicationConfig = {
	'mcp.enabled': true,
	'federation.enabled': true
};

export default {
	config: getConfig()
};
