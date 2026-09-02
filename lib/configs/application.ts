import {
	configStore,
	dpopNonceSecretStore,
	pairwiseSaltStore
} from '../adapters/index.js';
import { validateConfiguration, type Configuration } from './configuration.js';
import { resolveNonceSecret } from './nonceSecret.js';
import { initPairwiseSalt } from './pairwiseSalt.js';

export const ApplicationConfig = {
	/*
	 * authorization.allowOmittingSingleRegisteredRedirectUri
	 *
	 * title: Allow omitting the redirect_uri parameter when only a single one is registered for a client.
	 *
	 * description: When enabled, an authorization request (and the authorization-code token exchange)
	 * that omits redirect_uri is resolved to the client's sole registered redirect_uri. This is a
	 * deviation from strict OAuth 2.1 (which expects redirect_uri present); it is isolated behind this
	 * named flag and defaults to disabled (secure-by-default) so omission is an explicit opt-in.
	 */
	'authorization.allowOmittingSingleRegisteredRedirectUri': false,

	/*
	 * pushedAuthorizationRequests
	 *
	 * title: [`RFC9126`](https://www.rfc-editor.org/rfc/rfc9126.html) - OAuth 2.0 Pushed Authorization Requests (`PAR`)
	 *
	 * description: Enables the use of `pushed_authorization_request_endpoint` defined by the Pushed
	 * Authorization Requests RFC.
	 */
	'par.enabled': false,
	/*
	 * allowUnregisteredRedirectUris
	 *
	 * description: Allows unregistered redirect_uri values to be used by authenticated clients using PAR that do not use a `sector_identifier_uri`.
	 */
	'par.allowUnregisteredRedirectUris': false,

	/*
	 * features.dPoP
	 *
	 * title: [`RFC9449`](https://www.rfc-editor.org/rfc/rfc9449.html) - OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer (`DPoP`)
	 *
	 * description: Enables `DPoP` - mechanism for sender-constraining tokens via a
	 * proof-of-possession mechanism on the application level.
	 */
	'dpop.enabled': false,
	/**
	 * features.dPoP.nonceSecret
	 *
	 * description: The secret every server-provided DPoP nonce is derived from. A 32-byte Buffer.
	 *
	 * Server-owned state, not an operator setting: it is deliberately absent from the admin settings
	 * catalog, and since the settings API filters submissions against that catalog, no operator can
	 * reach it. The server provisions one at startup when its store holds none (configs/nonceSecret.ts),
	 * so this is `undefined` only in the instant before that resolution runs — never while serving.
	 *
	 * An in-process bootstrap may supply one, which is the only way a value arrives from outside, and
	 * is how the test suite pins a fixed secret. A supplied value that is not 32 bytes is ignored in
	 * favour of the stored one rather than being fatal.
	 *
	 * The widening is needed because the initial value is `undefined` while the resolved value is byte
	 * material; TypeScript infers the literal's type from the initialiser alone, and there is no way to
	 * annotate one property of an object literal in place. `Uint8Array` rather than `Buffer` for the
	 * reason given on isUsableNonceSecret: a Buffer is one, and a structured clone of this object
	 * downgrades it to one.
	 */
	'dpop.nonceSecret': undefined as Uint8Array | undefined,
	/**
	 * features.dPoP.requireNonce
	 *
	 * description: Determine whether a DPoP nonce is required or not.
	 */
	'dpop.requireNonce': false,
	/**
	 * features.dPoP.allowReplay
	 *
	 * description: Controls whether DPoP Proof Replay Detection is used or not.
	 */
	'dpop.allowReplay': false,

	/*
	 * features.introspection
	 *
	 * title: [`RFC7662`](https://www.rfc-editor.org/rfc/rfc7662.html) - OAuth 2.0 Token Introspection
	 *
	 * description: Enables Token Introspection for:
	 *   - opaque access tokens
	 *   - refresh tokens
	 */
	'introspection.enabled': false,

	/*
	 * features.jwtResponseModes
	 *
	 * title: [JWT Secured Authorization Response Mode (`JARM`)](https://openid.net/specs/oauth-v2-jarm-final.html)
	 *
	 * description: Enables JWT Secured Authorization Responses
	 */
	'responseMode.jwt.enabled': false,

	/*
	 * features.fapi
	 *
	 * title: Financial-grade API Security Profile (`FAPI`)
	 *
	 * description: Enables extra Authorization Server behaviours defined in FAPI that cannot be
	 * achieved by other configuration options.
	 *
	 * '2.0' Enables behaviours from [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-security-profile-2_0-final.html)
	 */
	'fapi.enabled': false,

	/*
	 * features.clientCredentials
	 *
	 * title: [`RFC6749`](https://www.rfc-editor.org/rfc/rfc6749.html#section-1.3.4) - Client Credentials
	 *
	 * description: Enables `grant_type=client_credentials` to be used on the token endpoint.
	 */
	'clientCredentials.enabled': false,

	/*
	 * refreshToken
	 *
	 * description: Advertises `grant_type=refresh_token` even when the client is not
	 *   requesting the `offline_access` scope. Issuance itself is governed by the
	 *   `issueRefreshToken` addon; this flag only controls grant-type advertisement
	 *   (it replaces the former `issueRefreshToken !== default` boot-time heuristic).
	 */
	'refreshToken.enabled': false,

	/*
	 * features.backchannelLogout
	 *
	 * title: [`OIDC Back-Channel Logout 1.0`](https://openid.net/specs/openid-connect-backchannel-1_0-final.html)
	 *
	 * description: Enables Back-Channel Logout features.
	 */
	'backchannelLogout.enabled': false,

	/*
	 * features.encryption
	 *
	 * description: Enables encryption features such as receiving encrypted UserInfo responses,
	 * encrypted ID Tokens and signing/encrypting Request Objects.
	 */
	'encryption.enabled': false,

	/*
	 * features.jwtIntrospection
	 *
	 * title: [JWT Response for OAuth Token Introspection - RFC9701](https://www.rfc-editor.org/rfc/rfc9701.html)
	 *
	 * description: Enables JWT responses for Token Introspection features. Only available in
	 * conjunction with `introspection.enabled`.
	 */
	'jwtIntrospection.enabled': false,

	/*
	 * features.jwtUserinfo
	 *
	 * description: Enables JWT responses for the UserInfo endpoint. Only available in conjunction
	 * with `userinfo.enabled`.
	 */
	'jwtUserinfo.enabled': false,

	/*
	 * features.revocation
	 *
	 * title: [`RFC7009`](https://www.rfc-editor.org/rfc/rfc7009.html) - OAuth 2.0 Token Revocation
	 *
	 * description: Enables Token Revocation.
	 */
	'revocation.enabled': false,

	/*
	 * features.userinfo
	 *
	 * description: Enables the UserInfo endpoint.
	 */
	'userinfo.enabled': true,

	/*
	 * features.rpInitiatedLogout
	 *
	 * title: [`OIDC RP-Initiated Logout 1.0`](https://openid.net/specs/openid-connect-rpinitiated-1_0-final.html)
	 *
	 * description: Enables RP-Initiated Logout features.
	 */
	'rpInitiatedLogout.enabled': true,

	/*
	 * features.claimsParameter
	 *
	 * title: [`claims` parameter](https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter)
	 *
	 * description: Enables the use and validations of the `claims` parameter.
	 */
	'claimsParameter.enabled': false,

	/*
	 * features.mTLS
	 *
	 * title: [`RFC8705`](https://www.rfc-editor.org/rfc/rfc8705.html) - OAuth 2.0 Mutual TLS Client Authentication and Certificate-Bound Access Tokens
	 *
	 * description: Enables specific features from the Mutual TLS specification.
	 */
	'mTLS.enabled': false,
	/*
	 * features.mTLS.certificateBoundAccessTokens
	 *
	 * description: Enables Mutual TLS Client Certificate-Bound Tokens.
	 */
	'mTLS.certificateBoundAccessTokens': false,
	/*
	 * features.mTLS.selfSignedTlsClientAuth
	 *
	 * description: Enables the `self_signed_tls_client_auth` client authentication method.
	 */
	'mTLS.selfSignedTlsClientAuth': false,
	/*
	 * features.mTLS.tlsClientAuth
	 *
	 * description: Enables the `tls_client_auth` client authentication method.
	 */
	'mTLS.tlsClientAuth': false,

	/*
	 * features.deviceFlow
	 *
	 * title: [`RFC8628`](https://www.rfc-editor.org/rfc/rfc8628.html) - OAuth 2.0 Device Authorization Grant (Device Flow)
	 *
	 * description: Enables Device Authorization Grant features.
	 */
	'deviceFlow.enabled': false,
	/*
	 * features.deviceFlow.charset
	 *
	 * description: Character set for generated user codes — `base-20` or `digits`.
	 */
	'deviceFlow.charset': 'base-20',
	/*
	 * features.deviceFlow.mask
	 *
	 * description: Template for generated user codes; `*` is replaced by random chars from the charset.
	 */
	'deviceFlow.mask': '****-****',

	/*
	 * features.ciba
	 *
	 * title: [OIDC Client Initiated Backchannel Authentication Flow (`CIBA`)](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0-final.html)
	 *
	 * description: Enables Core `CIBA` Flow.
	 */
	'ciba.enabled': false,
	/*
	 * features.ciba.deliveryModes
	 *
	 * description: Supported token delivery modes — any of `poll`, `ping`.
	 */
	'ciba.deliveryModes': ['poll'],

	/*
	 * features.requestObjects
	 *
	 * title: [`JAR`](https://www.rfc-editor.org/rfc/rfc9101.html) - JWT Secured Authorization Request
	 *
	 * description: Enables the use and validation of the `request` (Request Object) parameter.
	 */
	'requestObjects.enabled': false,
	/*
	 * features.requestObjects.requireSignedRequestObject
	 *
	 * description: Makes signed request objects required for all authorization requests.
	 */
	'requestObjects.requireSignedRequestObject': false,

	/*
	 * features.resourceIndicators
	 *
	 * title: [`RFC8707`](https://www.rfc-editor.org/rfc/rfc8707.html) - Resource Indicators for OAuth 2.0
	 *
	 * description: Enables Resource Indicators features.
	 */
	'resourceIndicators.enabled': true,

	/*
	 * features.richAuthorizationRequests
	 *
	 * title: [`RFC9396`](https://www.rfc-editor.org/rfc/rfc9396.html) - OAuth 2.0 Rich Authorization Requests
	 *
	 * description: Enables the use of the `authorization_details` parameter.
	 */
	'richAuthorizationRequests.enabled': false,
	/*
	 * features.richAuthorizationRequests.types
	 *
	 * description: The authorization details types this server accepts, as a map of type identifier to
	 * a serializable descriptor:
	 *
	 *   {
	 *     'https://scheme.example/payment': {
	 *       label: 'Initiate a payment',            // required — what the consent screen shows
	 *       fields: {                               // optional constraints on the RFC 9396 §2 fields
	 *         actions: { required: true, allowed: ['initiate', 'status'] },
	 *         locations: {}, datatypes: {}, privileges: {},
	 *         identifier: { required: false }       // single-valued: no `allowed`
	 *       },
	 *       allowUnknownFields: false               // default — §5 requires refusing unknown fields
	 *     }
	 *   }
	 *
	 * The identifier is opaque: §2.1 leaves it to the server and recommends a collision-resistant
	 * namespace such as a URI. Every member is JSON, so the map round-trips through storage and the
	 * admin settings API. A per-type `validate` function may still be supplied in an in-process
	 * bootstrap as an escape hatch for semantics a descriptor cannot express; it is optional, and a
	 * rejection from it surfaces as `invalid_authorization_details`. Enabling the feature with an empty
	 * map fails validation, because every request would then be refused.
	 */
	'richAuthorizationRequests.types': {},

	/*
	 * cors
	 *
	 * title: Cross-Origin Resource Sharing for browser-based clients
	 *
	 * description: Enables the CORS layer: public metadata endpoints answer any origin, and the
	 * endpoints a browser app calls directly answer origins listed on the owning project's
	 * `corsOrigins`. Defaults to enabled because closure is achieved by data — a project with no
	 * origins grants nothing, so a fresh deployment is closed with this on. It exists as an incident
	 * kill switch. There is deliberately no `cors.maxAge` companion: the preflight cache lifetime is
	 * dictated by browser behaviour, not by deployment, and would be the first numeric key here.
	 */
	'cors.enabled': true,

	/*
	 * rateLimit
	 *
	 * title: Per-origin request rate limiting
	 *
	 * description: Refuses requests from a calling origin that exceeds its allowance inside a window,
	 * before the endpoint does any work. Allowances are tiered by route class rather than blanket: a
	 * number tight enough to protect the token endpoint would refuse the admin console's asset burst.
	 * Defaults to enabled — an authorization server reachable from the internet with no volume limit at
	 * all is the condition this exists to end — and the switch is here as an incident kill switch.
	 *
	 * Counting is per instance and held in memory, never persisted. Two consequences the operator
	 * documentation states rather than hides: with N machines serving concurrently the effective
	 * allowance is N times the configured value, and an instance restart clears every counter it held.
	 * This is therefore a resource protection, not a security boundary — the properties that must hold
	 * absolutely live in the per-identity throttles (lib/helpers/rate_window.ts, verification attempt
	 * caps), which this leaves untouched.
	 */
	'rateLimit.enabled': true,
	/*
	 * rateLimit.trustedProxy
	 *
	 * description: Whether the forwarded-origin headers (Fly-Client-IP, then the first hop of
	 * X-Forwarded-For, then X-Real-IP) name the caller. This is the one setting here with a wrong answer
	 * in each direction, so it is stated rather than defaulted silently: true while directly exposed
	 * lets any caller rotate the header per request and never be limited; false while behind a proxy
	 * puts the entire internet into one bucket and refuses everyone within seconds. Defaults to true to
	 * match the shipped fly.toml — the failure it risks is bypass, and the opposite default risks a
	 * total outage on the deployment this repository actually ships.
	 */
	'rateLimit.trustedProxy': true,
	/*
	 * rateLimit.maxTrackedOrigins
	 *
	 * description: How many origins each route class remembers at once. Bounded because the key is
	 * client-supplied: an unbounded counter map is itself the memory-exhaustion vector the limiter was
	 * added to prevent, and on a 1 GB machine that is strictly worse than having no limiter. When the
	 * bound is reached the least recently seen origin is evicted and gets a fresh allowance, which fails
	 * open under an address-rotation flood the limiter cannot stop anyway, and never fails closed
	 * against honest traffic.
	 */
	'rateLimit.maxTrackedOrigins': 10000,
	/*
	 * rateLimit.strict.*
	 *
	 * description: The allowance for the unauthenticated and expensive surface — token issuance,
	 * authorization, dynamic registration, device and CIBA, and every end-user door that verifies a
	 * secret or sends mail. Set at the issue's own sixty per minute rather than tighter: a confidential
	 * client's backend behind one address doing legitimate token exchanges is the false-refusal case
	 * that matters, and sixty a minute still stops a flood cold, since a flood is thousands a second.
	 */
	'rateLimit.strict.max': 60,
	'rateLimit.strict.windowSeconds': 60,
	/*
	 * rateLimit.ordinary.*
	 *
	 * description: The allowance for everything not otherwise classified — userinfo, introspection,
	 * revocation, the admin plane, the MCP surface, and the rest of the interaction screens. This is the
	 * class an unclassified route falls into, so it is sized for a mixed browser-and-backend session
	 * rather than for any one endpoint.
	 */
	'rateLimit.ordinary.max': 300,
	'rateLimit.ordinary.windowSeconds': 60,
	/*
	 * rateLimit.public.*
	 *
	 * description: The allowance for the cheap public surface — static assets, discovery metadata, the
	 * key set — and for every preflight, whatever it precedes. Sized to clear the admin console's full
	 * page-and-asset load comfortably: these responses are static documents, so limiting them tightly
	 * would break discovery for a whole NAT before it protected anything.
	 */
	'rateLimit.public.max': 1200,
	'rateLimit.public.windowSeconds': 60,

	/*
	 * loginThrottle
	 *
	 * title: Brute-force throttle on the password sign-in door
	 *
	 * description: Counts failed password attempts per bucket-and-address pair and shuts that door once
	 * the cap is reached, refusing every further attempt — including one carrying the correct password —
	 * until the window elapses. Each further exhaustion shuts it for longer, doubling to the ceiling.
	 * The refusal is the ordinary "invalid username or password" page: it reveals neither the throttle
	 * nor whether the address exists, and it costs no password hashing, so a flood against one address
	 * stops being a CPU cost as well as stopping being a guessing opportunity.
	 *
	 * Unlike `rateLimit` this is persisted through the adapter, so it holds across restarts and across
	 * concurrently serving machines. That is the difference between a resource protection and a
	 * security boundary, and it is why THERE IS DELIBERATELY NO `loginThrottle.enabled`: an incident
	 * kill switch here is a switch that returns the server to the vulnerability. The keys below are
	 * bounded to a range in which the protection still means something (lib/configs/configuration.ts)
	 * instead of accepting a value that disables it.
	 *
	 * A counter is cleared by a verifying password, and by a *completed* password reset — consuming the
	 * emailed secret proves control of the address, which is the escape an attacker guessing passwords
	 * does not have. A bucket that requires a second factor stays at the first window however often it
	 * is exhausted: a guessed password there is not a sign-in, and the reserved admin bucket has no
	 * self-service reset to escape with.
	 */

	/*
	 * loginThrottle.failureCap
	 *
	 * description: Failed password attempts tolerated per window for one address. Matches the
	 * verification code's attempt cap, so the server has one answer to "how many tries does a secret
	 * get". Raising it hands an attacker proportionally more guesses per window; lowering it locks out
	 * users who mistype. Capped at 100 because that is where the protection stops being one.
	 */
	'loginThrottle.failureCap': 5,
	/*
	 * loginThrottle.windowSeconds
	 *
	 * description: How long the door stays shut the first time an address exhausts the cap, and the
	 * base the escalation doubles from. Also the flat window for a bucket that requires a second
	 * factor. This doubles as an honest user's shortest lockout, so it is the number to lower if
	 * legitimate lockouts are the complaint.
	 */
	'loginThrottle.windowSeconds': 900,
	/*
	 * loginThrottle.windowCeilingSeconds
	 *
	 * description: The longest the door will shut, however many windows an address has exhausted. With
	 * the defaults the curve is 15 → 30 → 60 minutes, holding a sustained attacker to about 120 guesses
	 * a day. This is also an honest user's worst case if they cannot use a password reset, which is why
	 * it is not larger: the counter's own retention (24h from the last failure) bounds it from above,
	 * and the validator refuses a ceiling below the first window.
	 */
	'loginThrottle.windowCeilingSeconds': 3600,

	/*
	 * federation
	 *
	 * title: Upstream OIDC federation — let end users sign in through an external identity provider
	 *
	 * description: Enables per-bucket federated sign-in: a bucket may carry generic OIDC providers, and
	 * its login page offers them alongside (or instead of) the password form. This server acts as a
	 * relying party on the upstream provider — OIDC Core/Discovery 1.0 with PKCE where the provider
	 * advertises it — and discards the upstream's access and refresh tokens once the identity assertion
	 * verifies.
	 *
	 * Defaults to disabled because it is the only feature here that lets an outside party's assertion
	 * produce a session on this server: off, no `/federation/*` route is served and no provider control
	 * renders, whatever any bucket holds. The routes that *configure* providers are deliberately not
	 * gated by this, so an operator can prepare a provider before switching it on — and can still delete
	 * one on a deployment that has just switched it off.
	 */
	'federation.enabled': false,

	/*
	 * features.registration
	 *
	 * title: [`OIDC Dynamic Client Registration 1.0`](https://openid.net/specs/openid-connect-registration-1_0-final.html) and [`RFC7591`](https://www.rfc-editor.org/rfc/rfc7591.html) - OAuth 2.0 Dynamic Client Registration Protocol
	 *
	 * description: Enables Dynamic Client Registration.
	 */
	'registration.enabled': false,
	/*
	 * features.registration.initialAccessToken
	 *
	 * description: Requires a valid initial access token for registration. `string` (static) or
	 * `boolean` (adapter-backed).
	 */
	'registration.initialAccessToken': false,
	/*
	 * features.registration.policies
	 *
	 * description: Registration/registration-management policies applied to client properties.
	 */
	'registration.policies': undefined,
	/*
	 * features.registration.issueRegistrationAccessToken
	 *
	 * description: Whether (or a function deciding whether) a registration access token is issued.
	 */
	'registration.issueRegistrationAccessToken': true,

	/*
	 * features.registrationManagement
	 *
	 * title: [`OAuth 2.0 Dynamic Client Registration Management Protocol`](https://www.rfc-editor.org/rfc/rfc7592.html)
	 *
	 * description: Enables Update and Delete features for dynamically registered clients.
	 */
	'registrationManagement.enabled': false,
	/*
	 * features.registrationManagement.rotateRegistrationAccessToken
	 *
	 * description: Enables registration access token rotation (boolean or function).
	 */
	'registrationManagement.rotateRegistrationAccessToken': true,

	/*
	 * scopes
	 *
	 * description: Array of additional scope values that the authorization server signals to support in the discovery
	 *   endpoint. Only add scopes the authorization server has a corresponding resource for.
	 *   Resource Server scopes don't belong here, see `features.resourceIndicators` for configuring
	 *   those.
	 */
	scopes: ['openid', 'offline_access'],

	/*
	 * claims
	 *
	 * description: Claims map used to derive `claims_supported` and claim-defined scopes for discovery.
	 *   `{ claimName: null }` exposes a standalone claim; `{ scopeName: ['claim', ...] }` groups claims under a scope.
	 */
	claims: {
		acr: null,
		sid: null,
		auth_time: null,
		iss: null,
		openid: ['sub']
	},

	/*
	 * acrValues
	 *
	 * description: Authentication Context Class References the server supports; surfaced as `acr_values_supported`.
	 */
	acrValues: [],

	/*
	 * conformIdTokenClaims
	 *
	 * title: ID Token only contains End-User claims when the requested `response_type` is `id_token`
	 */
	conformIdTokenClaims: true,

	/*
	 * discovery
	 *
	 * description: Pass additional properties to this object to extend the discovery document.
	 *   Relocated here as the single source for server-owned settings, but intentionally absent
	 *   from the admin settings catalog: it is not operator-editable, so it is neither returned by
	 *   nor writable through the settings API.
	 */
	discovery: {
		claim_types_supported: ['normal'],
		claims_locales_supported: undefined,
		display_values_supported: undefined,
		op_policy_uri: undefined,
		op_tos_uri: undefined,
		service_documentation: undefined,
		ui_locales_supported: undefined
	},

	/*
	 * clientAuthMethods
	 *
	 * description: Supported client authentication methods; surfaced as `token_endpoint_auth_methods_supported`.
	 *   mTLS methods are added on top when the corresponding mTLS options are enabled.
	 */
	clientAuthMethods: [
		'client_secret_basic',
		'client_secret_jwt',
		'client_secret_post',
		'private_key_jwt',
		'none'
	],

	/*
	 * mcp.enabled
	 *
	 * title: Administrative MCP control plane
	 *
	 * description: Serves the administrative control plane to an AI agent over MCP at `/mcp`, as an
	 *   OAuth 2.1 protected resource of this server. Every operation runs through the same admin
	 *   routes, authorization and audit trail the console uses.
	 *
	 * Off by default, unlike every other capability here that defaults on. The switch hands an agent
	 *   the authority of the administrator who authorized it, so a deployment should reach for it
	 *   deliberately rather than inherit it from an upgrade.
	 */
	'mcp.enabled': false,

	/*
	 * errorStore.enabled
	 *
	 * title: Server error store — record unexpected internal faults for later analysis
	 *
	 * description: Records every unexpected internal fault to durable storage, so a failure can be
	 *   diagnosed after it happened instead of only while it is happening. Routine client rejections
	 *   (a bad grant, a wrong password, an expired code) are correct behaviour and are never recorded:
	 *   every entry in the store is a defect.
	 *
	 * Off by default. With it off nothing is written and none of the `/admin/api/errors` paths are
	 *   served — they answer exactly as a path this server does not have.
	 */
	'errorStore.enabled': false,
	/*
	 * errorStore.retentionDays
	 *
	 * description: How long a recorded fault is kept. A group's expiry is advanced on every occurrence,
	 *   so a fault that is still happening does not age out mid-life.
	 */
	'errorStore.retentionDays': 30,
	/*
	 * errorStore.maxGroups
	 *
	 * description: How many distinct faults are retained. When the bound is reached the *least recently
	 *   seen* group is evicted — never the oldest by creation, which would discard a long-running fault
	 *   in favour of one that happened once this morning.
	 */
	'errorStore.maxGroups': 10000,
	/*
	 * errorStore.samplesPerGroup
	 *
	 * description: How many full occurrences are kept per distinct fault. The occurrence *count* stays
	 *   exact however many samples are discarded: this bounds the detail retained, never the tally.
	 */
	'errorStore.samplesPerGroup': 10,
	/*
	 * errorStore.queueDepth
	 *
	 * description: How many records may await writing. Recording never delays a response, so a fault is
	 *   queued rather than written inline — and this is therefore also the stated loss bound: a process
	 *   killed abruptly can lose at most this many records, and a full queue counts what it could not
	 *   accept rather than blocking the request or failing silently.
	 */
	'errorStore.queueDepth': 500,
	/*
	 * errorStore.originCaptureLevel
	 *
	 * description: How much of the caller's network origin a record keeps, because an address is
	 *   personal data: `omitted` stores none and says so, `anonymized` stores a value that cannot be
	 *   reversed to the address but is still equal for two requests from the same origin, and `full`
	 *   stores the address.
	 *
	 * One key with one default in every deployment, rather than a value derived from the deployment
	 *   mode: the two modes must differ by configuration, never by a branch in logic. A
	 *   compliance-bound deployment lowers it; one tracing abuse raises it.
	 */
	'errorStore.originCaptureLevel': 'anonymized',

	/*
	 * There is deliberately no `errorStore.mcpPurgeEnabled`.
	 *
	 * The specification asked for agent purging to be an operator opt-in. It cannot be one, and a setting
	 * that did nothing would be worse than its absence: the published MCP operation set is invariant under
	 * capability switches, which `test/mcp/capability_invariance.spec.ts` asserts twice over — on the tool
	 * list under every flag combination, and on `lib/mcp/server.ts` containing no flag read at all.
	 *
	 * Purging is therefore withheld from agents outright, alongside project and bucket deletion. The
	 * exclusion table in `lib/mcp/catalogue.ts` records the same reasoning at the point it takes effect.
	 */

	/*
	 * sentry.enabled
	 *
	 * title: Sentry integration — report recorded faults to an external monitoring project
	 *
	 * description: Sends every fault the error store records to an operator-supplied Sentry project,
	 *   so a failure raises an alert instead of waiting to be found in the console. This is an
	 *   additional destination, never an alternative: a fault is recorded locally first and the
	 *   outbound event is derived from that record, which is why switching this on requires
	 *   `errorStore.enabled`.
	 *
	 * Off by default. With it off no client is created and nothing leaves this server.
	 */
	'sentry.enabled': false,
	/*
	 * sentry.dsn
	 *
	 * description: The ingestion credential of the receiving Sentry project.
	 *
	 * Deliberately absent from the settings catalog, so no read surface can return it: the generic
	 *   `/admin/api/settings` projection is built by iterating that catalog, and its PUT refuses any
	 *   key the catalog does not describe. It is written and read only through
	 *   `/admin/api/settings/sentry`, which reports whether one is stored and never what it is —
	 *   the same treatment `dpop.nonceSecret` gets, and for the same reason.
	 *
	 * Stored in plaintext, unlike a client secret. This is a credential this server *presents*, not
	 *   one it verifies, so a hash would make it useless; it sits beside the private signing keys the
	 *   datastore already holds.
	 */
	'sentry.dsn': ''
	/*
	 * There are deliberately no `sentry.environment` or `sentry.release` settings.
	 *
	 * Both are properties of the deployment rather than decisions an operator makes: the environment
	 *   is NODE_ENV and the release is this package's version, both already declared by the
	 *   deployment. They were operator-entered once and should not have been — a release label kept by
	 *   hand goes stale on the first deploy nobody remembers to edit, and a stale label is worse than
	 *   none because it sends an investigation to a build that never ran. See sentry/labels.ts.
	 */
	/*
	 * There is deliberately no `sentry.queueDepth` either.
	 *
	 * The outbound queue is bounded — it has to be — but the bound is a constant in sentry/dispatch.ts
	 *   rather than a setting, and that file records why: it limits loss of the *second* copy of a
	 *   fault, not the only one, and there is no question an operator could answer to choose a value.
	 */
};
Object.assign(ApplicationConfig, await configStore.get());

/*
 * Resolved here, between loading the persisted settings and validating them, and the position is the
 * point. The validator below rejects "nonces required with no usable secret"; if that rule could ever
 * run before this line, it would fail a perfectly healthy boot. Two consecutive statements in one
 * module make the ordering a fact rather than a property of the import graph — which is why this is
 * not a side-effect import from event_bus.ts, the way signing keys are anchored.
 *
 * Every entry path imports this module, so nothing can serve a request before this has completed.
 */
ApplicationConfig['dpop.nonceSecret'] = await resolveNonceSecret(
	dpopNonceSecretStore,
	ApplicationConfig['dpop.nonceSecret']
);

/*
 * The pairwise salt is resolved here for the ordering reason above, but it is deliberately NOT an
 * ApplicationConfig key. The nonce secret is one because the validator below cross-checks it against
 * dpop.requireNonce; nothing validates the salt against another setting, so a key would buy nothing
 * and cost the catalogue exclusion, the settings-merge exclusion and the test that pins its absence.
 * It lives as module state in configs/pairwiseSalt.ts, the way signing keys live in configs/keys.ts.
 *
 * Driven from here rather than resolved inside that module because its consumer, addon/tokens.ts, is a
 * leaf the model graph imports: a store import there would close a cycle back into a module still
 * evaluating. So the store is handed in, and this line is what guarantees the salt is settled before
 * any request — every entry path imports this module.
 */
await initPairwiseSalt(pairwiseSaltStore);

export type ApplicationConfigType = typeof ApplicationConfig;

/*
 * configuration
 *
 * The values derived from the settings above — collections as Sets, and the results of
 * cross-referencing scopes against claims. Validated here, at the point the settings finish
 * loading, so an unrunnable configuration fails at startup and no code can observe an
 * unvalidated one. Read flat from ApplicationConfig for anything not listed here.
 *
 * Mutated in place by reloadConfiguration, never reassigned, so every module holding the imported
 * reference sees the current values — the same rule the key material follows (configs/keystore.ts).
 */
export const configuration: Configuration =
	validateConfiguration(ApplicationConfig);

/*
 * reloadConfiguration
 *
 * Re-derive after ApplicationConfig has been changed in place. The settings are boot-only in a
 * deployment — they are persisted and applied by a restart — so this exists for the tests, which
 * reconfigure the server per spec and would otherwise be reading values derived from the previous
 * spec's settings.
 */
export function reloadConfiguration(): Configuration {
	Object.assign(configuration, validateConfiguration(ApplicationConfig));
	return configuration;
}
