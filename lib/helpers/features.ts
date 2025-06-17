export const STABLE = new Set([
	'backchannelLogout',
	'ciba',
	'claimsParameter',
	'clientCredentials',
	'deviceFlow',
	'devInteractions',
	'dPoP',
	'encryption',
	'fapi',
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
		},
		externalSigningSupport: {
			name: 'External Signing Key Support',
			version: ['experimental-01']
		}
	})
);
