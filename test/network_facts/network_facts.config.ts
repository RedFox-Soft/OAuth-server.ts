import getConfig from '../default.config.js';

const config = getConfig();

/* The download on; nothing here sends usage reports, so the version stays out of the user agent unless a case asks. */
export const ApplicationConfig = {
	'networkFacts.enabled': true,
	'telemetry.enabled': false
};

export default {
	config
};
