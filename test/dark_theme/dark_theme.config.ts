import getConfig from '../default.config.js';

const config = getConfig();

// Pages are rendered through their renderers; nothing here reaches a protocol endpoint.
export const ApplicationConfig = {};

export default {
	config
};
