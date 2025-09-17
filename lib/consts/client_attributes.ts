const RECOGNIZED_METADATA = [
	'application_type',
	'client_id_issued_at',
	'client_name',
	'client_secret_expires_at',
	'client_uri',
	'contacts',
	'default_acr_values',
	'default_max_age',
	'grant_types',
	'id_token_signed_response_alg',
	'initiate_login_uri',
	'jwks_uri',
	'jwks',
	'logo_uri',
	'policy_uri',
	'require_auth_time',
	'response_types',
	'response_modes',
	'scope',
	'sector_identifier_uri',
	'subject_type',
	'token_endpoint_auth_method',
	'tos_uri'
];

const DEFAULT = {
	application_type: 'web',
	authorization_signed_response_alg: 'RS256',
	backchannel_logout_session_required: false,
	backchannel_user_code_parameter: false,
	grant_types: ['authorization_code'],
	id_token_signed_response_alg: 'RS256',
	introspection_signed_response_alg: 'RS256',
	post_logout_redirect_uris: [],
	require_auth_time: false,
	require_signed_request_object: false,
	dpop_bound_access_tokens: false,
	response_types: ['code'],
	subject_type: 'public',
	tls_client_certificate_bound_access_tokens: false,
	token_endpoint_auth_method: 'client_secret_basic',
	authorization_details_types: []
};

const BOOL = [
	'backchannel_logout_session_required',
	'backchannel_user_code_parameter',
	'dpop_bound_access_tokens',
	'require_auth_time',
	'require_signed_request_object',
	'tls_client_certificate_bound_access_tokens',
	'use_mtls_endpoint_aliases'
];

const ARYS = [
	'contacts',
	'default_acr_values',
	'grant_types',
	'post_logout_redirect_uris',
	'response_types',
	'response_modes',
	'authorization_details_types'
];

const STRING = [
	'application_type',
	'authorization_encrypted_response_alg',
	'authorization_encrypted_response_enc',
	'authorization_signed_response_alg',
	'backchannel_authentication_request_signing_alg',
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
	'request_object_signing_alg',
	'scope',
	'sector_identifier_uri',
	'subject_type',
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
	'grant_types',
	'post_logout_redirect_uris',
	'response_types',
	'response_modes',
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

const WEB_URI = [
	'backchannel_client_notification_endpoint',
	'backchannel_logout_uri',
	'client_uri',
	'initiate_login_uri',
	'jwks_uri',
	'logo_uri',
	'policy_uri',
	'sector_identifier_uri',
	'tos_uri'
];

const HTTPS_URI = [
	'backchannel_client_notification_endpoint',
	'initiate_login_uri',
	'sector_identifier_uri'
];

const LOOPBACKS = new Set(['localhost', '127.0.0.1', '[::1]']);

const ENUM = {
	application_type: () => ['native', 'web']
};

export const noVSCHAR = /[^\x20-\x7E]/;

export {
	ARYS,
	BOOL,
	DEFAULT,
	ENUM,
	HTTPS_URI,
	LOOPBACKS,
	RECOGNIZED_METADATA,
	STRING,
	WEB_URI,
	WHEN
};
