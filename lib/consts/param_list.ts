import { t } from 'elysia';

export const AuthorizationParameters = t.Object({
	client_id: t.String(),
	redirect_uri: t.Optional(t.String()),
	response_type: t.String(),

	state: t.Optional(t.String()),
	claims_locales: t.Optional(t.Array(t.String())),
	code_challenge: t.Optional(t.String()),
	code_challenge_method: t.Optional(t.String()),
	display: t.Optional(t.String()),
	id_token_hint: t.Optional(t.String()),
	login_hint: t.Optional(t.String()),
	max_age: t.Optional(t.Number()),
	nonce: t.Optional(t.String()),
	prompt: t.Optional(t.String()),
	scope: t.Optional(t.String()),
	response_mode: t.Optional(t.String()),
	registration: t.Optional(t.String()),
	request: t.Optional(t.String()),
	request_uri: t.Optional(t.String()),
	ui_locales: t.Optional(t.Array(t.String())),
	acr_values: t.Optional(t.String()),

	// added conditionally depending on feature flag which will be checked in the code
	web_message_uri: t.Optional(t.String()),
	claims: t.Optional(t.Object({})),
	resource: t.Optional(t.Array(t.String())),
	authorization_details: t.Optional(t.Array(t.Object({}))),
	dpop_jkt: t.Optional(t.String())
});

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
