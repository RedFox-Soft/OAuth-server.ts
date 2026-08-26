import getConfig from '../default.config.js';
import { ApplicationConfig } from 'lib/configs/application.ts';

/*
 * The agent surface with both capabilities on. The MCP plane is off by default, and so is the error
 * store, so a spec that forgets either sees an unserved route or an empty store rather than a failure —
 * which is the one confusing outcome worth naming here.
 */
ApplicationConfig['mcp.enabled'] = true;
ApplicationConfig['errorStore.enabled'] = true;

const config = getConfig();

export default {
	config
};
