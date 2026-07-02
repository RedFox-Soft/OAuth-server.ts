import getConfig from '../default.config.js';

const config = getConfig();

export const ApplicationConfig = {
	'registrationManagement.enabled': true,
	'registrationManagement.rotateRegistrationAccessToken': false,
	'registration.enabled': true,
	'registration.initialAccessToken': true,
	'registration.policies': {
		'empty-policy': () => {}
	}
};

export default {
	config
};
