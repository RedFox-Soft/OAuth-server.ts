import getConfig from '../default.config.js';

/*
 * The capabilities a client the console registers can ask for: key-based client authentication, a
 * token from client credentials to prove it, and the request-security and logout switches whose
 * per-client attributes the admin surface now sets.
 */
export const ApplicationConfig = {
	...getConfig(),
	'clientCredentials.enabled': true,
	'par.enabled': true,
	'dpop.enabled': true,
	'requestObjects.enabled': true,
	'responseMode.jwt.enabled': true,
	'backchannelLogout.enabled': true,
	clientAuthMethods: [
		'client_secret_basic',
		'client_secret_jwt',
		'client_secret_post',
		'private_key_jwt',
		'none'
	]
};
