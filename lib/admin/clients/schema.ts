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

// Which of these a deployment admits is the `clientAuthMethods` setting's decision, checked by
// validateClient on every registration path; the mTLS methods need a certificate and are not offered.
const AuthMethod = t.Union([
	t.Literal('none'),
	t.Literal('client_secret_basic'),
	t.Literal('client_secret_post'),
	t.Literal('client_secret_jwt'),
	t.Literal('private_key_jwt')
]);

const JwkSet = t.Object({ keys: t.Array(t.Record(t.String(), t.Unknown())) });

const SubjectType = t.Union([t.Literal('public'), t.Literal('pairwise')]);

/*
 * The attributes a client authenticating with its own key, and a client held to FAPI's request
 * protections, is registered with — the ones dynamic registration always accepted and the console did
 * not. Validation is validateClient's, exactly as for a self-registered client: a key set with private
 * material, an algorithm the deployment does not support, or an attribute whose capability is off is
 * refused there, so nothing is restated here. `service.ts` maps each to its stored key.
 */
const creatable = {
	jwks: t.Optional(JwkSet),
	jwksUri: t.Optional(t.String()),
	tokenEndpointAuthSigningAlg: t.Optional(t.String()),
	idTokenSignedResponseAlg: t.Optional(t.String()),
	authorizationSignedResponseAlg: t.Optional(t.String()),
	requestObjectSigningAlg: t.Optional(t.String()),
	requireSignedRequestObject: t.Optional(t.Boolean()),
	requirePushedAuthorizationRequests: t.Optional(t.Boolean()),
	dpopBoundAccessTokens: t.Optional(t.Boolean()),
	backchannelLogoutUri: t.Optional(t.String()),
	backchannelLogoutSessionRequired: t.Optional(t.Boolean()),
	subjectType: t.Optional(SubjectType),
	sectorIdentifierUri: t.Optional(t.String())
};

// On an edit, null removes the attribute: moving from a key set URL to an inline key set is otherwise
// impossible, since the two may not both be registered.
const editable = {
	jwks: t.Optional(t.Union([JwkSet, t.Null()])),
	jwksUri: t.Optional(t.Union([t.String(), t.Null()])),
	tokenEndpointAuthSigningAlg: t.Optional(t.Union([t.String(), t.Null()])),
	idTokenSignedResponseAlg: t.Optional(t.Union([t.String(), t.Null()])),
	authorizationSignedResponseAlg: t.Optional(t.Union([t.String(), t.Null()])),
	requestObjectSigningAlg: t.Optional(t.Union([t.String(), t.Null()])),
	requireSignedRequestObject: t.Optional(t.Union([t.Boolean(), t.Null()])),
	requirePushedAuthorizationRequests: t.Optional(
		t.Union([t.Boolean(), t.Null()])
	),
	dpopBoundAccessTokens: t.Optional(t.Union([t.Boolean(), t.Null()])),
	backchannelLogoutUri: t.Optional(t.Union([t.String(), t.Null()])),
	backchannelLogoutSessionRequired: t.Optional(
		t.Union([t.Boolean(), t.Null()])
	),
	subjectType: t.Optional(t.Union([SubjectType, t.Null()])),
	sectorIdentifierUri: t.Optional(t.Union([t.String(), t.Null()]))
};

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
	authorizationDetailsTypes: t.Optional(t.Array(t.String())),
	...creatable
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
	authorizationDetailsTypes: t.Optional(t.Array(t.String())),
	...editable
});
