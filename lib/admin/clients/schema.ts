import { t } from 'elysia';

/*
 * Written as literal tuples, not `list.map((v) => t.Literal(v))`: a union built from a mapped array
 * validates the same but its route-level type is `never`, so the typed client (Eden) could send no
 * value at all and an array of them came out as `File[]`.
 */

// Grant types the provider supports (discovery grant_types_supported). The UI
// offers this full set (SP-2 decision: "all supported grants"); validateClient +
// the token endpoint's hasGrant gating remain the runtime source of truth.
const GrantType = t.Union([
	t.Literal('authorization_code'),
	t.Literal('refresh_token'),
	t.Literal('client_credentials'),
	t.Literal('urn:ietf:params:oauth:grant-type:device_code'),
	t.Literal('urn:openid:params:grant-type:ciba')
]);

const AuthMethod = t.Union([
	t.Literal('none'),
	t.Literal('client_secret_basic'),
	t.Literal('client_secret_post')
]);

export const CreateClientBody = t.Object({
	clientName: t.Optional(t.String({ minLength: 1 })),
	applicationType: t.Optional(t.Union([t.Literal('web'), t.Literal('native')])),
	grantTypes: t.Array(GrantType, {
		minItems: 1
	}),
	redirectUris: t.Optional(t.Array(t.String())),
	postLogoutRedirectUris: t.Optional(t.Array(t.String())),
	tokenEndpointAuthMethod: AuthMethod,
	scope: t.Optional(t.String()),
	requireConsent: t.Optional(t.Boolean()),
	backchannelTokenDeliveryMode: t.Optional(
		// 'push' is deliberately absent: nothing implements it (the backchannel result handler knows
		// 'ping', the CIBA request check knows 'poll') and checkCibaDeliveryModes refuses any mode
		// outside those two, so offering it could only ever produce a rejected client.
		t.Union([t.Literal('poll'), t.Literal('ping')])
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
		t.Array(GrantType, {
			minItems: 1
		})
	),
	redirectUris: t.Optional(t.Array(t.String())),
	postLogoutRedirectUris: t.Optional(t.Array(t.String())),
	tokenEndpointAuthMethod: t.Optional(AuthMethod),
	scope: t.Optional(t.String()),
	requireConsent: t.Optional(t.Boolean()),
	backchannelTokenDeliveryMode: t.Optional(
		// 'push' is deliberately absent: nothing implements it (the backchannel result handler knows
		// 'ping', the CIBA request check knows 'poll') and checkCibaDeliveryModes refuses any mode
		// outside those two, so offering it could only ever produce a rejected client.
		t.Union([t.Literal('poll'), t.Literal('ping')])
	),
	backchannelClientNotificationEndpoint: t.Optional(t.String()),
	authorizationDetailsTypes: t.Optional(t.Array(t.String()))
});
