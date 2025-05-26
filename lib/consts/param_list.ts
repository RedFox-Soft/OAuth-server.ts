import { t } from 'elysia';

export const AuthorizationParameters = t.Object({
	client_id: t.String(),
	redirect_uri: t.Optional(t.String({ format: 'uri' })),
	response_type: t.Optional(
		t.Union([t.Literal('code'), t.Literal('none')], {
			error: "Property 'response_type' should be one of: 'code', 'none'"
		})
	),

	state: t.Optional(t.String()),
	claims_locales: t.Optional(t.Array(t.String())),
	code_challenge: t.Optional(t.String({ pattern: '^[A-Za-z0-9_-]{43}$' })),
	code_challenge_method: t.Optional(t.Literal('S256')),
	display: t.Optional(t.String()),
	id_token_hint: t.Optional(t.String()),
	login_hint: t.Optional(t.String()),
	max_age: t.Optional(
		t.Numeric({
			minimum: 0,
			maximum: Number.MAX_SAFE_INTEGER,
			error: 'max_age must be a positive integer'
		})
	),
	nonce: t.Optional(t.String()),
	prompt: t.Optional(t.String()),
	scope: t.Optional(t.String()),
	response_mode: t.Optional(t.String()),
	registration: t.Optional(t.String()),
	request: t.Optional(t.String()),
	request_uri: t.Optional(t.String()),
	ui_locales: t.Optional(t.Array(t.String())),
	acr_values: t.Optional(t.String()),
	iss: t.Optional(t.String()),
	aud: t.Optional(t.String({ format: 'uri' })),

	// added conditionally depending on feature flag which will be checked in the code
	web_message_uri: t.Optional(t.String()),
	claims: t.Optional(
		t.ObjectString(
			{
				id_token: t.Optional(
					t.Object({}, { error: 'claims.id_token must be an object' })
				),
				userinfo: t.Optional(
					t.Object({}, { error: 'claims.userinfo must be an object' })
				)
			},
			{
				additionalProperties: false,
				error:
					'claims parameter should be object with userinfo or id_token properties'
			}
		)
	),
	resource: t.Optional(t.Array(t.String())),
	authorization_details: t.Optional(t.Array(t.Object({}))),
	dpop_jkt: t.Optional(t.String())
});

export const routeNames = {
	authorization: '/auth',
	backchannel_authentication: '/backchannel',
	code_verification: '/device',
	device_authorization: '/device/auth',
	end_session: '/session/end',
	introspection: '/token/introspection',
	jwks: '/jwks',
	pushed_authorization_request: '/par',
	registration: '/reg',
	revocation: '/token/revocation',
	token: '/token',
	userinfo: '/userinfo'
};

export const cookieNames = {
	interaction: '_interaction',
	session: '_session'
};

export const AuthorizationCookies = t.Cookie(
	{
		_interaction: t.Optional(t.String()),
		_session: t.Optional(t.String())
	},
	{ httpOnly: true, sameSite: 'strict' }
);

export const PARAM_LIST = [
	'acr_values',
	// 'claims', // added conditionally depending on feature flag
	'claims_locales',
	'client_id',
	'code_challenge',
	'code_challenge_method',
	'display',
	'id_token_hint',
	'login_hint',
	'max_age',
	'nonce',
	'prompt',
	'redirect_uri',
	'registration',
	'request',
	'request_uri',
	'response_mode',
	'response_type',
	'scope',
	'state',
	'ui_locales'
];
