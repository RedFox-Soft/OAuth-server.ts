import { t } from 'elysia';

// Grant types the provider supports (discovery grant_types_supported). The UI
// offers this full set (SP-2 decision: "all supported grants"); validateClient +
// the token endpoint's hasGrant gating remain the runtime source of truth.
export const SUPPORTED_GRANT_TYPES = [
	'authorization_code',
	'refresh_token',
	'client_credentials',
	'urn:ietf:params:oauth:grant-type:device_code',
	'urn:openid:params:grant-type:ciba'
] as const;

const AUTH_METHODS = [
	'none',
	'client_secret_basic',
	'client_secret_post'
] as const;

export const CreateClientBody = t.Object({
	clientName: t.Optional(t.String({ minLength: 1 })),
	applicationType: t.Optional(t.Union([t.Literal('web'), t.Literal('native')])),
	grantTypes: t.Array(t.Union(SUPPORTED_GRANT_TYPES.map((g) => t.Literal(g))), {
		minItems: 1
	}),
	redirectUris: t.Optional(t.Array(t.String())),
	postLogoutRedirectUris: t.Optional(t.Array(t.String())),
	tokenEndpointAuthMethod: t.Union(AUTH_METHODS.map((m) => t.Literal(m))),
	scope: t.Optional(t.String()),
	requireConsent: t.Optional(t.Boolean()),
	backchannelTokenDeliveryMode: t.Optional(
		t.Union([t.Literal('poll'), t.Literal('ping'), t.Literal('push')])
	),
	backchannelClientNotificationEndpoint: t.Optional(t.String()),
	// Per-client permitted RAR types (RFC 9396 §10.5). Without this on the admin surface no client an
	// operator creates could ever use the feature: the client metadata defaults to [], so every client
	// must opt in explicitly. Validation is delegated to validateClient, which recognizes the metadata
	// only when the feature is enabled and checks each value against the configured types.
	authorizationDetailsTypes: t.Optional(t.Array(t.String()))
});

export const UpdateClientBody = t.Object({
	clientName: t.Optional(t.String({ minLength: 1 })),
	applicationType: t.Optional(t.Union([t.Literal('web'), t.Literal('native')])),
	grantTypes: t.Optional(
		t.Array(t.Union(SUPPORTED_GRANT_TYPES.map((g) => t.Literal(g))), {
			minItems: 1
		})
	),
	redirectUris: t.Optional(t.Array(t.String())),
	postLogoutRedirectUris: t.Optional(t.Array(t.String())),
	tokenEndpointAuthMethod: t.Optional(
		t.Union(AUTH_METHODS.map((m) => t.Literal(m)))
	),
	scope: t.Optional(t.String()),
	requireConsent: t.Optional(t.Boolean()),
	backchannelTokenDeliveryMode: t.Optional(
		t.Union([t.Literal('poll'), t.Literal('ping'), t.Literal('push')])
	),
	backchannelClientNotificationEndpoint: t.Optional(t.String()),
	authorizationDetailsTypes: t.Optional(t.Array(t.String()))
});
