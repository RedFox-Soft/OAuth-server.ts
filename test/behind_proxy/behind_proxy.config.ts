import getConfig from '../default.config.js';

/*
 * Apps behind a proxy (specs/122). The feature has no switch of its own; the administrative MCP endpoint is on
 * because an agent's parity with the console is part of what the area proves. The projects, people and groups a
 * spec needs are seeded by `world()` in ./helpers.ts — a config declares settings and clients only.
 */
export const ApplicationConfig = {
	'mcp.enabled': true
};

export default {
	config: getConfig()
};
