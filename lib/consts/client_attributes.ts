const RECOGNIZED_METADATA = [
	'client_id_issued_at',
	'client_name',
	'client_secret_expires_at',
	'client_uri',
	'contacts',
	'default_acr_values',
	'default_max_age',
	'id_token_signed_response_alg',
	'initiate_login_uri',
	'jwks_uri',
	'jwks',
	'logo_uri',
	'policy_uri',
	'require_auth_time',
	'scope',
	'sector_identifier_uri',
	'token_endpoint_auth_method',
	'tos_uri'
];

const DEFAULT = {
	authorization_signed_response_alg: 'RS256',
	backchannel_logout_session_required: false,
	backchannel_user_code_parameter: false,
	id_token_signed_response_alg: 'RS256',
	introspection_signed_response_alg: 'RS256',
	post_logout_redirect_uris: [],
	require_auth_time: false,
	require_signed_request_object: false,
	dpop_bound_access_tokens: false,
	tls_client_certificate_bound_access_tokens: false,
	token_endpoint_auth_method: 'client_secret_basic',
	authorization_details_types: []
};

// BOOL removed: boolean type is now enforced declaratively in clientSchema.ts (TypeBox).

const ARYS = [
	'contacts',
	'default_acr_values',
	'post_logout_redirect_uris',
	'authorization_details_types'
];

const STRING = [
	'authorization_encrypted_response_alg',
	'authorization_encrypted_response_enc',
	'authorization_signed_response_alg',
	'backchannel_client_notification_endpoint',
	'backchannel_logout_uri',
	'backchannel_token_delivery_mode',
	'client_name',
	'client_uri',
	'id_token_encrypted_response_alg',
	'id_token_encrypted_response_enc',
	'id_token_signed_response_alg',
	'initiate_login_uri',
	'introspection_encrypted_response_alg',
	'introspection_encrypted_response_enc',
	'introspection_signed_response_alg',
	'jwks_uri',
	'logo_uri',
	'policy_uri',
	'request_object_encryption_alg',
	'request_object_encryption_enc',
	'scope',
	'sector_identifier_uri',
	'tls_client_auth_san_dns',
	'tls_client_auth_san_email',
	'tls_client_auth_san_ip',
	'tls_client_auth_san_uri',
	'tls_client_auth_subject_dn',
	'token_endpoint_auth_method',
	'tos_uri',
	'userinfo_encrypted_response_alg',
	'userinfo_encrypted_response_enc',
	'userinfo_signed_response_alg',

	// in arrays
	'contacts',
	'default_acr_values',
	'post_logout_redirect_uris',
	'authorization_details_types'
];

const WHEN = {
	authorization_encrypted_response_enc: [
		'authorization_encrypted_response_alg',
		'A128CBC-HS256'
	],
	id_token_encrypted_response_enc: [
		'id_token_encrypted_response_alg',
		'A128CBC-HS256'
	],
	introspection_encrypted_response_enc: [
		'introspection_encrypted_response_alg',
		'A128CBC-HS256'
	],
	request_object_encryption_enc: [
		'request_object_encryption_alg',
		'A128CBC-HS256'
	],
	userinfo_encrypted_response_enc: [
		'userinfo_encrypted_response_alg',
		'A128CBC-HS256'
	],

	id_token_encrypted_response_alg: ['id_token_signed_response_alg'],
	userinfo_encrypted_response_alg: ['userinfo_signed_response_alg'],
	introspection_encrypted_response_alg: ['introspection_signed_response_alg'],
	authorization_encrypted_response_alg: ['authorization_signed_response_alg']
};

// WEB_URI / HTTPS_URI removed: web/https URL shapes are now enforced declaratively
// in lib/configs/clientSchema.ts (TypeBox formats), not by the engine's webUris() pass.

const LOOPBACKS = new Set(['localhost', '127.0.0.1', '[::1]']);

export const noVSCHAR = /[^\x20-\x7E]/;

export { ARYS, DEFAULT, LOOPBACKS, RECOGNIZED_METADATA, STRING, WHEN };
