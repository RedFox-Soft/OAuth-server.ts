import getConfig from '../default.config.js';

const config = getConfig();

// Every discovery-gating feature flag enabled, so the discovery document advertises all
// feature-gated keys. Discovery reads these from ApplicationConfig.
export const ApplicationConfig = {
	'par.enabled': true,
	'dpop.enabled': true,
	'introspection.enabled': true,
	'claimsParameter.enabled': true,
	'deviceFlow.enabled': true,
	'rpInitiatedLogout.enabled': true,
	'registration.enabled': true,
	'revocation.enabled': true,
	'backchannelLogout.enabled': true,
	'mTLS.enabled': true,
	'mTLS.certificateBoundAccessTokens': true,
	'mTLS.tlsClientAuth': true,
	'mTLS.selfSignedTlsClientAuth': true,
	'ciba.enabled': true,
	'richAuthorizationRequests.enabled': true,
	'encryption.enabled': true,
	'requestObjects.enabled': true,
	'requestObjects.requireSignedRequestObject': true,
	'userinfo.enabled': true,
	'jwtUserinfo.enabled': true,
	'responseMode.jwt.enabled': true,
	'jwtIntrospection.enabled': true
};

export default {
	config
};
