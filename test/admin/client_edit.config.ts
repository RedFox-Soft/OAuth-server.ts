import getConfig from '../default.config.js';

export const PAYMENT_TYPE = 'https://scheme.example/payment';

/*
 * Every capability that makes a registration attribute recognisable is on, so the preservation guard
 * in client_edit.spec.ts ranges over the widest attribute set a deployment can have. Pairwise needs no
 * switch: `subject_type` is always recognised.
 */
export const ApplicationConfig = {
	...getConfig(),
	'backchannelLogout.enabled': true,
	'ciba.enabled': true,
	clientAuthMethods: [
		'client_secret_basic',
		'client_secret_jwt',
		'client_secret_post',
		'private_key_jwt',
		'tls_client_auth',
		'none'
	],
	'ciba.deliveryModes': ['poll', 'ping'],
	'encryption.enabled': true,
	'introspection.enabled': true,
	'jwtIntrospection.enabled': true,
	'jwtUserinfo.enabled': true,
	'mTLS.enabled': true,
	'mTLS.certificateBoundAccessTokens': true,
	'mTLS.tlsClientAuth': true,
	'requestObjects.enabled': true,
	'responseMode.jwt.enabled': true,
	'richAuthorizationRequests.enabled': true,
	'richAuthorizationRequests.types': {
		[PAYMENT_TYPE]: { label: 'Initiate a payment' }
	},
	'rpInitiatedLogout.enabled': true
};
