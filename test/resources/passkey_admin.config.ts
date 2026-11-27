import getConfig from '../default.config.js';

/*
 * Admin and MCP parity harness for an API requiring a passkey (specs/143 US1).
 */
export const ApplicationConfig = {
	...getConfig(),
	'mcp.enabled': true
};

export default { config: getConfig() };
