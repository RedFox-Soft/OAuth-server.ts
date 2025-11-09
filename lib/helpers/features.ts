export const STABLE = new Set([
	'backchannelLogout',
	'ciba',
	'claimsParameter',
	'clientCredentials',
	'deviceFlow',
	'devInteractions',
	'dPoP',
	'encryption',
	'introspection',
	'jwtResponseModes',
	'jwtIntrospection',
	'jwtUserinfo',
	'mTLS',
	'registration',
	'registrationManagement',
	'requestObjects',
	'resourceIndicators',
	'revocation',
	'rpInitiatedLogout',
	'userinfo'
]);

export const EXPERIMENTS = new Map(
	Object.entries({
		richAuthorizationRequests: {
			name: 'OAuth 2.0 Rich Authorization Requests',
			version: ['experimental-01']
		}
	})
);
