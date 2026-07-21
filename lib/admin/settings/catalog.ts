import { ApplicationConfig } from '../../configs/application.js';

export type SettingType = 'boolean' | 'string' | 'enum' | 'string-array';

export interface SettingDescriptor {
	key: keyof typeof ApplicationConfig;
	group: string;
	label: string;
	description: string;
	type: SettingType;
	options?: string[];
	dependsOn?: keyof typeof ApplicationConfig;
}

const CLIENT_AUTH_METHODS = [
	'client_secret_basic',
	'client_secret_jwt',
	'client_secret_post',
	'private_key_jwt',
	'none'
];

// Single source of truth for the editable settings: drives the API whitelist,
// server-side validation, and the UI form. Descriptions are condensed from the
// doc-comments in lib/configs/application.ts.
export const SETTINGS_CATALOG: SettingDescriptor[] = [
	{ key: 'par.enabled', group: 'PAR', label: 'Enable PAR (RFC 9126)', type: 'boolean', description: 'Enables the pushed_authorization_request endpoint.' },
	{ key: 'par.allowUnregisteredRedirectUris', group: 'PAR', label: 'Allow unregistered redirect_uris via PAR', type: 'boolean', dependsOn: 'par.enabled', description: 'Lets authenticated PAR clients use unregistered redirect_uri values (no sector_identifier_uri).' },

	{ key: 'dpop.enabled', group: 'DPoP', label: 'Enable DPoP (RFC 9449)', type: 'boolean', description: 'Sender-constrains tokens via application-layer proof-of-possession.' },
	{ key: 'dpop.requireNonce', group: 'DPoP', label: 'Require DPoP nonce', type: 'boolean', dependsOn: 'dpop.enabled', description: 'Requires a server-provided DPoP nonce.' },
	{ key: 'dpop.allowReplay', group: 'DPoP', label: 'Allow DPoP proof replay', type: 'boolean', dependsOn: 'dpop.enabled', description: 'Disables DPoP proof replay detection.' },

	{ key: 'introspection.enabled', group: 'Introspection', label: 'Enable Token Introspection (RFC 7662)', type: 'boolean', description: 'Enables introspection for opaque access tokens and refresh tokens.' },
	{ key: 'jwtIntrospection.enabled', group: 'Introspection', label: 'JWT introspection responses (RFC 9701)', type: 'boolean', dependsOn: 'introspection.enabled', description: 'JWT responses for introspection. Requires Introspection enabled.' },

	{ key: 'responseMode.jwt.enabled', group: 'JWT Response Modes', label: 'Enable JARM', type: 'boolean', description: 'Enables JWT Secured Authorization Responses.' },

	{ key: 'fapi.enabled', group: 'FAPI', label: 'Enable FAPI behaviours', type: 'boolean', description: 'Extra Authorization Server behaviours defined in the FAPI profile.' },

	{ key: 'clientCredentials.enabled', group: 'Client Credentials', label: 'Enable client_credentials grant', type: 'boolean', description: 'Enables grant_type=client_credentials on the token endpoint.' },

	{ key: 'devInteractions.enabled', group: 'Development', label: 'Enable dev interaction views', type: 'boolean', description: 'Development-only out-of-the-box interaction views. Disable in production.' },

	{ key: 'backchannelLogout.enabled', group: 'Back-Channel Logout', label: 'Enable Back-Channel Logout', type: 'boolean', description: 'Enables OIDC Back-Channel Logout features.' },

	{ key: 'encryption.enabled', group: 'Encryption', label: 'Enable encryption features', type: 'boolean', description: 'Encrypted UserInfo/ID Tokens and signed/encrypted Request Objects.' },

	{ key: 'userinfo.enabled', group: 'UserInfo', label: 'Enable the UserInfo endpoint', type: 'boolean', description: 'Enables the UserInfo endpoint.' },
	{ key: 'jwtUserinfo.enabled', group: 'UserInfo', label: 'JWT UserInfo responses', type: 'boolean', dependsOn: 'userinfo.enabled', description: 'JWT responses for UserInfo. Requires UserInfo enabled.' },

	{ key: 'revocation.enabled', group: 'Revocation', label: 'Enable Token Revocation (RFC 7009)', type: 'boolean', description: 'Enables Token Revocation.' },

	{ key: 'rpInitiatedLogout.enabled', group: 'RP-Initiated Logout', label: 'Enable RP-Initiated Logout', type: 'boolean', description: 'Enables OIDC RP-Initiated Logout.' },

	{ key: 'claimsParameter.enabled', group: 'Claims Parameter', label: 'Enable the claims parameter', type: 'boolean', description: 'Enables use and validation of the claims parameter.' },

	{ key: 'mTLS.enabled', group: 'mTLS', label: 'Enable mTLS features (RFC 8705)', type: 'boolean', description: 'Enables Mutual TLS client authentication / certificate-bound tokens.' },
	{ key: 'mTLS.certificateBoundAccessTokens', group: 'mTLS', label: 'Certificate-bound access tokens', type: 'boolean', dependsOn: 'mTLS.enabled', description: 'Requires mTLS enabled.' },
	{ key: 'mTLS.selfSignedTlsClientAuth', group: 'mTLS', label: 'self_signed_tls_client_auth method', type: 'boolean', dependsOn: 'mTLS.enabled', description: 'Requires mTLS enabled.' },
	{ key: 'mTLS.tlsClientAuth', group: 'mTLS', label: 'tls_client_auth method', type: 'boolean', dependsOn: 'mTLS.enabled', description: 'Requires mTLS enabled.' },

	{ key: 'deviceFlow.enabled', group: 'Device Flow', label: 'Enable Device Authorization Grant (RFC 8628)', type: 'boolean', description: 'Enables the Device Authorization Grant.' },
	{ key: 'deviceFlow.charset', group: 'Device Flow', label: 'User-code charset', type: 'enum', options: ['base-20', 'digits'], dependsOn: 'deviceFlow.enabled', description: 'Character set for generated user codes.' },
	{ key: 'deviceFlow.mask', group: 'Device Flow', label: 'User-code mask', type: 'string', dependsOn: 'deviceFlow.enabled', description: 'Template for user codes; * is replaced by a random charset char.' },

	{ key: 'ciba.enabled', group: 'CIBA', label: 'Enable CIBA flow', type: 'boolean', description: 'Enables Core CIBA flow.' },
	{ key: 'ciba.deliveryModes', group: 'CIBA', label: 'Token delivery modes', type: 'string-array', options: ['poll', 'ping'], dependsOn: 'ciba.enabled', description: 'Supported CIBA token delivery modes.' },

	{ key: 'requestObjects.enabled', group: 'Request Objects', label: 'Enable Request Objects (JAR)', type: 'boolean', description: 'Enables the request (Request Object) parameter.' },
	{ key: 'requestObjects.requireSignedRequestObject', group: 'Request Objects', label: 'Require signed request objects', type: 'boolean', dependsOn: 'requestObjects.enabled', description: 'Requires signed request objects for all authorization requests.' },

	{ key: 'resourceIndicators.enabled', group: 'Resource Indicators', label: 'Enable Resource Indicators (RFC 8707)', type: 'boolean', description: 'Enables Resource Indicators features.' },

	{ key: 'richAuthorizationRequests.enabled', group: 'Rich Authorization Requests', label: 'Enable RAR (RFC 9396)', type: 'boolean', description: 'Enables the authorization_details parameter.' },

	{ key: 'registration.enabled', group: 'Registration', label: 'Enable Dynamic Client Registration', type: 'boolean', description: 'Enables Dynamic Client Registration.' },
	{ key: 'registration.issueRegistrationAccessToken', group: 'Registration', label: 'Issue registration access token', type: 'boolean', dependsOn: 'registration.enabled', description: 'Whether a registration access token is issued.' },

	{ key: 'registrationManagement.enabled', group: 'Registration Management', label: 'Enable registration management (RFC 7592)', type: 'boolean', description: 'Enables update/delete for dynamically registered clients.' },
	{ key: 'registrationManagement.rotateRegistrationAccessToken', group: 'Registration Management', label: 'Rotate registration access token', type: 'boolean', dependsOn: 'registrationManagement.enabled', description: 'Enables registration access token rotation.' },

	{ key: 'scopes', group: 'Discovery', label: 'Supported scopes', type: 'string-array', description: 'Scopes advertised in discovery. Must include openid.' },
	{ key: 'acrValues', group: 'Discovery', label: 'Supported acr values', type: 'string-array', description: 'ACR values the server supports (acr_values_supported).' },
	{ key: 'clientAuthMethods', group: 'Discovery', label: 'Client authentication methods', type: 'string-array', options: CLIENT_AUTH_METHODS, description: 'token_endpoint_auth_methods_supported (mTLS methods added when enabled).' }
];
