import { ApplicationConfig } from '../../configs/application.js';

export type SettingType =
	| 'boolean'
	| 'string'
	| 'enum'
	| 'number'
	| 'string-array'
	// A structured JSON value edited as text. The route validates only that it is an object; its real
	// rules belong to validateConfiguration, so boot and the admin PUT cannot disagree.
	| 'json';

export interface SettingDescriptor {
	key: keyof typeof ApplicationConfig;
	group: string;
	label: string;
	description: string;
	type: SettingType;
	options?: string[];
	dependsOn?: keyof typeof ApplicationConfig;
	/*
	 * The setting enables a feature implemented from a draft spec, so its behaviour can change in a
	 * way a finalised one would not. Purely informational — it tells an operator what they are
	 * turning on, and nothing in the server behaves differently because of it.
	 *
	 * No entry sets this today: RAR was the last one, and it now tracks published RFC 9396. Kept
	 * because it is catalog vocabulary rather than dead code — the next feature tracked from a draft
	 * needs it, and this comment is the only place the concept is explained.
	 */
	experimental?: boolean;
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
	{
		key: 'authorization.allowOmittingSingleRegisteredRedirectUri',
		group: 'Authorization',
		label: 'Allow omitting a single registered redirect_uri',
		type: 'boolean',
		description:
			'When a client has exactly one registered redirect_uri, allow authorization and token requests to omit redirect_uri and resolve it to that single value. Off by default (secure).'
	},

	{
		key: 'par.enabled',
		group: 'PAR',
		label: 'Enable PAR (RFC 9126)',
		type: 'boolean',
		description: 'Enables the pushed_authorization_request endpoint.'
	},
	{
		key: 'par.allowUnregisteredRedirectUris',
		group: 'PAR',
		label: 'Allow unregistered redirect_uris via PAR',
		type: 'boolean',
		dependsOn: 'par.enabled',
		description:
			'Lets authenticated PAR clients use unregistered redirect_uri values (no sector_identifier_uri).'
	},

	{
		key: 'dpop.enabled',
		group: 'DPoP',
		label: 'Enable DPoP (RFC 9449)',
		type: 'boolean',
		description:
			'Sender-constrains tokens via application-layer proof-of-possession.'
	},
	/*
	 * `dpop.nonceSecret` is deliberately absent, and this is the record of why.
	 *
	 * It is server-provisioned state, not an operator setting: the server generates a 32-byte secret at
	 * startup when its store holds none, and replaces a stored one that reads back unusable
	 * (configs/nonceSecret.ts). An operator never supplies, sees, or rotates it — so there is nothing
	 * here to edit, and its absence from this catalog is what makes the settings API unable to reach it.
	 * Pinned in both directions by test/admin/settings_catalog.spec.ts.
	 *
	 * Turning the setting below on therefore has no prerequisite an operator can fail to meet. Before
	 * this was true, arming it with no secret in place was accepted and answered every DPoP-bearing
	 * request with a 500 after the next restart.
	 */
	{
		key: 'dpop.requireNonce',
		group: 'DPoP',
		label: 'Require DPoP nonce',
		type: 'boolean',
		dependsOn: 'dpop.enabled',
		description:
			'Requires a server-provided DPoP nonce. The secret the nonces are derived from is managed by the server; there is nothing to supply.'
	},
	{
		key: 'dpop.allowReplay',
		group: 'DPoP',
		label: 'Allow DPoP proof replay',
		type: 'boolean',
		dependsOn: 'dpop.enabled',
		description: 'Disables DPoP proof replay detection.'
	},

	{
		key: 'introspection.enabled',
		group: 'Introspection',
		label: 'Enable Token Introspection (RFC 7662)',
		type: 'boolean',
		description:
			'Enables introspection for opaque access tokens and refresh tokens.'
	},
	{
		key: 'jwtIntrospection.enabled',
		group: 'Introspection',
		label: 'JWT introspection responses (RFC 9701)',
		type: 'boolean',
		dependsOn: 'introspection.enabled',
		description:
			'JWT responses for introspection. Requires Introspection enabled.'
	},

	{
		key: 'responseMode.jwt.enabled',
		group: 'JWT Response Modes',
		label: 'Enable JARM',
		type: 'boolean',
		description: 'Enables JWT Secured Authorization Responses.'
	},

	{
		key: 'fapi.enabled',
		group: 'FAPI',
		label: 'Enable FAPI behaviours',
		type: 'boolean',
		description:
			'Extra Authorization Server behaviours defined in the FAPI profile.'
	},

	{
		key: 'clientCredentials.enabled',
		group: 'Client Credentials',
		label: 'Enable client_credentials grant',
		type: 'boolean',
		description: 'Enables grant_type=client_credentials on the token endpoint.'
	},

	{
		key: 'backchannelLogout.enabled',
		group: 'Back-Channel Logout',
		label: 'Enable Back-Channel Logout',
		type: 'boolean',
		description: 'Enables OIDC Back-Channel Logout features.'
	},

	{
		key: 'encryption.enabled',
		group: 'Encryption',
		label: 'Enable encryption features',
		type: 'boolean',
		description:
			'Encrypted UserInfo/ID Tokens and signed/encrypted Request Objects.'
	},

	{
		key: 'userinfo.enabled',
		group: 'UserInfo',
		label: 'Enable the UserInfo endpoint',
		type: 'boolean',
		description: 'Enables the UserInfo endpoint.'
	},
	{
		key: 'jwtUserinfo.enabled',
		group: 'UserInfo',
		label: 'JWT UserInfo responses',
		type: 'boolean',
		dependsOn: 'userinfo.enabled',
		description: 'JWT responses for UserInfo. Requires UserInfo enabled.'
	},

	{
		key: 'revocation.enabled',
		group: 'Revocation',
		label: 'Enable Token Revocation (RFC 7009)',
		type: 'boolean',
		description: 'Enables Token Revocation.'
	},

	{
		key: 'rpInitiatedLogout.enabled',
		group: 'RP-Initiated Logout',
		label: 'Enable RP-Initiated Logout',
		type: 'boolean',
		description: 'Enables OIDC RP-Initiated Logout.'
	},

	{
		key: 'claimsParameter.enabled',
		group: 'Claims Parameter',
		label: 'Enable the claims parameter',
		type: 'boolean',
		description: 'Enables use and validation of the claims parameter.'
	},

	{
		key: 'mTLS.enabled',
		group: 'mTLS',
		label: 'Enable mTLS features (RFC 8705)',
		type: 'boolean',
		description:
			'Enables Mutual TLS client authentication / certificate-bound tokens.'
	},
	{
		key: 'mTLS.certificateBoundAccessTokens',
		group: 'mTLS',
		label: 'Certificate-bound access tokens',
		type: 'boolean',
		dependsOn: 'mTLS.enabled',
		description: 'Requires mTLS enabled.'
	},
	{
		key: 'mTLS.selfSignedTlsClientAuth',
		group: 'mTLS',
		label: 'self_signed_tls_client_auth method',
		type: 'boolean',
		dependsOn: 'mTLS.enabled',
		description: 'Requires mTLS enabled.'
	},
	{
		key: 'mTLS.tlsClientAuth',
		group: 'mTLS',
		label: 'tls_client_auth method',
		type: 'boolean',
		dependsOn: 'mTLS.enabled',
		description: 'Requires mTLS enabled.'
	},

	{
		key: 'deviceFlow.enabled',
		group: 'Device Flow',
		label: 'Enable Device Authorization Grant (RFC 8628)',
		type: 'boolean',
		description: 'Enables the Device Authorization Grant.'
	},
	{
		key: 'deviceFlow.charset',
		group: 'Device Flow',
		label: 'User-code charset',
		type: 'enum',
		options: ['base-20', 'digits'],
		dependsOn: 'deviceFlow.enabled',
		description: 'Character set for generated user codes.'
	},
	{
		key: 'deviceFlow.mask',
		group: 'Device Flow',
		label: 'User-code mask',
		type: 'string',
		dependsOn: 'deviceFlow.enabled',
		description:
			'Template for user codes; * is replaced by a random charset char.'
	},

	{
		key: 'ciba.enabled',
		group: 'CIBA',
		label: 'Enable CIBA flow',
		type: 'boolean',
		description: 'Enables Core CIBA flow.'
	},
	{
		key: 'ciba.deliveryModes',
		group: 'CIBA',
		label: 'Token delivery modes',
		type: 'string-array',
		options: ['poll', 'ping'],
		dependsOn: 'ciba.enabled',
		description: 'Supported CIBA token delivery modes.'
	},

	{
		key: 'requestObjects.enabled',
		group: 'Request Objects',
		label: 'Enable Request Objects (JAR)',
		type: 'boolean',
		description: 'Enables the request (Request Object) parameter.'
	},
	{
		key: 'requestObjects.requireSignedRequestObject',
		group: 'Request Objects',
		label: 'Require signed request objects',
		type: 'boolean',
		dependsOn: 'requestObjects.enabled',
		description:
			'Requires signed request objects for all authorization requests.'
	},

	{
		key: 'resourceIndicators.enabled',
		group: 'Resource Indicators',
		label: 'Enable Resource Indicators (RFC 8707)',
		type: 'boolean',
		description: 'Enables Resource Indicators features.'
	},

	{
		key: 'richAuthorizationRequests.enabled',
		group: 'Rich Authorization Requests',
		label: 'Enable RAR (RFC 9396)',
		type: 'boolean',
		description:
			'Enables the authorization_details parameter, per RFC 9396 (published May 2023). Requires at least one authorization details type below, and requires Resource Indicators — details are only assigned to an access token bound to a resource server.'
	},
	{
		key: 'richAuthorizationRequests.types',
		group: 'Rich Authorization Requests',
		label: 'Authorization details types',
		type: 'json',
		dependsOn: 'richAuthorizationRequests.enabled',
		description:
			'The authorization details types this server accepts, as a map of type identifier to a descriptor: {"https://scheme.example/payment":{"label":"Initiate a payment","fields":{"actions":{"required":true,"allowed":["initiate"]}},"allowUnknownFields":false}}. `label` is what the consent screen shows. Constraints may only name the RFC 9396 §2 common fields (actions, locations, datatypes, privileges, identifier); `identifier` is single-valued so it takes `required` only. Unknown fields are refused unless a type opts in.'
	},

	{
		key: 'cors.enabled',
		group: 'CORS',
		label: 'Enable cross-origin access for browser clients',
		type: 'boolean',
		description:
			'Lets browser-based apps read responses from the metadata and key endpoints, and from the endpoints listed on a project’s browser origins. Closure normally comes from data — a project with no origins grants nothing — so this is an incident kill switch rather than the usual control.'
	},

	{
		key: 'rateLimit.enabled',
		group: 'Rate limiting',
		label: 'Refuse a calling origin that exceeds its request allowance',
		type: 'boolean',
		description:
			'Refuses requests from one origin past its allowance inside a window, before the endpoint does any work. Allowances are tiered by route class, so the token endpoint and a static asset are not held to the same number. On by default; turn it off as an incident kill switch if it starts refusing traffic it should not. Applied at startup.'
	},
	{
		key: 'rateLimit.trustedProxy',
		group: 'Rate limiting',
		label: 'Take the caller’s address from the proxy headers',
		type: 'boolean',
		dependsOn: 'rateLimit.enabled',
		description:
			'Whether Fly-Client-IP, the first hop of X-Forwarded-For, or X-Real-IP names the caller. This one has a wrong answer in each direction. Leave it ON when a proxy or load balancer sits in front of this server: with it off, every caller arrives as the proxy’s address, so the whole internet shares one allowance and all traffic is refused within seconds. Turn it OFF only when the server is directly exposed: with it on, any caller can set the header to a fresh value per request and is never limited. Defaults to on, matching the shipped deployment.'
	},
	{
		key: 'rateLimit.maxTrackedOrigins',
		group: 'Rate limiting',
		label: 'Origins remembered per route class',
		type: 'number',
		dependsOn: 'rateLimit.enabled',
		description:
			'How many distinct origins each class tracks at once, capping the limiter’s own memory. Bounded on purpose: the key comes from the caller, so an unbounded tally would itself become the memory-exhaustion vector this feature exists to prevent. Past the bound the least recently seen origin is forgotten and gets a fresh allowance. Lower it on a small machine.'
	},
	{
		key: 'rateLimit.strict.max',
		group: 'Rate limiting',
		label: 'Strict allowance — requests per window',
		type: 'number',
		dependsOn: 'rateLimit.enabled',
		description:
			'Applies to the unauthenticated and expensive surface: token issuance, authorization, dynamic registration, device and CIBA, and every end-user door that checks a secret or sends mail. Raise it if a legitimate server-to-server integration behind a single address, or many users behind one corporate NAT, start seeing refusals.'
	},
	{
		key: 'rateLimit.strict.windowSeconds',
		group: 'Rate limiting',
		label: 'Strict allowance — window length in seconds',
		type: 'number',
		dependsOn: 'rateLimit.enabled',
		description:
			'The period the strict allowance is measured over. A caller timing requests around the boundary can send close to twice the allowance across two adjacent windows; that is normal for this kind of limit and not a defect.'
	},
	{
		key: 'rateLimit.ordinary.max',
		group: 'Rate limiting',
		label: 'Ordinary allowance — requests per window',
		type: 'number',
		dependsOn: 'rateLimit.enabled',
		description:
			'Applies to everything not classified strict or public: userinfo, introspection, revocation, the administration API, the MCP surface, and the rest of the end-user screens. Any endpoint added without an explicit classification lands here, so it is sized for a mixed session rather than for one endpoint.'
	},
	{
		key: 'rateLimit.ordinary.windowSeconds',
		group: 'Rate limiting',
		label: 'Ordinary allowance — window length in seconds',
		type: 'number',
		dependsOn: 'rateLimit.enabled',
		description: 'The period the ordinary allowance is measured over.'
	},
	{
		key: 'rateLimit.public.max',
		group: 'Rate limiting',
		label: 'Public allowance — requests per window',
		type: 'number',
		dependsOn: 'rateLimit.enabled',
		description:
			'Applies to the cheap public surface — static assets, the discovery document, the key set — and to every cross-origin preflight. Sized to clear the administration console’s full page-and-asset load from one address. Raise it if the console stutters while loading.'
	},
	{
		key: 'rateLimit.public.windowSeconds',
		group: 'Rate limiting',
		label: 'Public allowance — window length in seconds',
		type: 'number',
		dependsOn: 'rateLimit.enabled',
		description: 'The period the public allowance is measured over.'
	},

	/*
	 * Three numbers and no switch. `dependsOn` is deliberately unset on all three: there is nothing to
	 * depend on, because the throttle has no `enabled` key — it is a security boundary, and an
	 * incident kill switch for it is a switch that reopens the vulnerability. Out-of-range values are
	 * refused by the same validator the server boots through, so the console cannot save a setting the
	 * server would not start with.
	 */
	{
		key: 'loginThrottle.failureCap',
		group: 'Login throttle',
		label: 'Failed password attempts allowed per window',
		type: 'number',
		description:
			'How many wrong passwords one address may submit before the sign-in door shuts for that address. Once shut it refuses every attempt, including one with the correct password, until the window ends — and the refusal looks exactly like an ordinary wrong password, so it tells an attacker nothing. Raising this hands a guessing attack proportionally more tries; lowering it locks out people who mistype. Matches the verification code’s attempt cap by default. Applied at startup.'
	},
	{
		key: 'loginThrottle.windowSeconds',
		group: 'Login throttle',
		label: 'First lockout length in seconds',
		type: 'number',
		description:
			'How long the door stays shut the first time an address runs out of attempts, and the length each further lockout doubles from. This is also the shortest wait an honest user who trips the throttle will face, so it is the number to lower if legitimate lockouts are the complaint. A bucket that requires a one-time code stays at this length however often it is tripped, because a guessed password there does not sign anyone in. Applied at startup.'
	},
	{
		key: 'loginThrottle.windowCeilingSeconds',
		group: 'Login throttle',
		label: 'Longest lockout length in seconds',
		type: 'number',
		description:
			'The longest the door will ever shut, however many times one address has run out of attempts. With the defaults the lockouts run 15 → 30 → 60 minutes, which holds a sustained attack to roughly 120 guesses a day. Cannot be shorter than the first lockout, and cannot exceed 24 hours — beyond that the counter would be forgotten before its own lockout ended, which would reopen the door. Someone locked out this long can still get straight back in by completing a password reset. Applied at startup.'
	},

	/*
	 * The switch stands alone: which providers exist, and whether any is enabled, is per-bucket data
	 * reached through the bucket's own routes rather than a setting here. Catalogued because a feature an
	 * operator cannot turn on without editing the database is not a feature they have.
	 */
	{
		key: 'federation.enabled',
		group: 'Federation',
		label: 'Enable sign-in through an upstream identity provider',
		type: 'boolean',
		description:
			'Lets a user bucket offer sign-in through external OpenID Providers configured on that bucket, alongside or instead of its password form. Off by default: this is the only capability that lets an outside party’s assertion produce a session here, and with it off no federation route is served and no provider button renders, whatever a bucket holds. Configuring providers stays available either way, so a provider can be prepared before switching this on and removed after switching it off. Applied at startup.'
	},

	/*
	 * The one capability whose subject is this console rather than the OAuth surface: it decides
	 * whether an AI agent may administer the instance. Grouped on its own so it cannot be mistaken
	 * for a protocol feature toggled during conformance work.
	 */
	{
		key: 'mcp.enabled',
		group: 'Administration',
		label: 'Enable the administrative MCP control plane',
		type: 'boolean',
		description:
			'Serves this control plane to an AI agent over MCP at /mcp, as an OAuth 2.1 protected resource of this server. An agent acts as the administrator who authorized it and gets exactly that account’s permissions: every operation runs through the same routes, the same checks and the same audit trail as the console, and each entry records both the operator and the agent. Deleting a project or a user bucket is withheld from agents entirely and stays console-only. Off by default — with it off, neither /mcp nor its metadata document is served. Applied at startup.'
	},

	{
		key: 'errorStore.enabled',
		group: 'Error Store',
		label: 'Record internal server faults',
		type: 'boolean',
		description:
			'Keeps a durable record of unexpected internal faults so a failure can be diagnosed after it happened rather than only while it is happening. Routine client rejections — a bad grant, a wrong password, an expired code — are correct behaviour and are never recorded, so every entry is a defect. Off by default; with it off nothing is written and the /admin/api/errors paths are not served at all.'
	},
	{
		key: 'errorStore.retentionDays',
		group: 'Error Store',
		label: 'Retention window (days)',
		type: 'number',
		dependsOn: 'errorStore.enabled',
		description:
			'How long a recorded fault is kept. The window runs from when the fault was last seen, not when it was first seen, so a fault that is still happening does not age out mid-life.'
	},
	{
		key: 'errorStore.maxGroups',
		group: 'Error Store',
		label: 'Maximum distinct faults retained',
		type: 'number',
		dependsOn: 'errorStore.enabled',
		description:
			'How many distinct faults are kept. At the limit the least recently seen fault is evicted — never the oldest by creation, which would discard a long-running problem in favour of one that happened once this morning.'
	},
	{
		key: 'errorStore.samplesPerGroup',
		group: 'Error Store',
		label: 'Occurrences kept per fault',
		type: 'number',
		dependsOn: 'errorStore.enabled',
		description:
			'How many full occurrences are retained for each distinct fault: the earliest, plus the most recent ones. The occurrence count stays exact however many are discarded — this bounds the detail kept, never the tally.'
	},
	{
		key: 'errorStore.queueDepth',
		group: 'Error Store',
		label: 'Pending write queue depth',
		type: 'number',
		dependsOn: 'errorStore.enabled',
		description:
			'How many records may await writing. Recording never delays a response, so faults are queued rather than written inline — which makes this also the loss bound: an abruptly killed process can lose at most this many records, and a full queue counts what it could not accept so an operator can see that recording fell behind.'
	},
	{
		key: 'errorStore.originCaptureLevel',
		group: 'Error Store',
		label: 'Caller address detail',
		type: 'enum',
		options: ['omitted', 'anonymized', 'full'],
		dependsOn: 'errorStore.enabled',
		description:
			'How much of the caller’s network address a record keeps, because an address is personal data. "omitted" stores none and says so; "anonymized" stores a value that cannot be reversed to the address but is still the same for two requests from one origin, so a single misbehaving deployment is still identifiable; "full" stores the address. Defaults to anonymized.'
	},

	{
		key: 'registration.enabled',
		group: 'Registration',
		label: 'Enable Dynamic Client Registration',
		type: 'boolean',
		description: 'Enables Dynamic Client Registration.'
	},
	{
		key: 'registration.issueRegistrationAccessToken',
		group: 'Registration',
		label: 'Issue registration access token',
		type: 'boolean',
		dependsOn: 'registration.enabled',
		description: 'Whether a registration access token is issued.'
	},

	{
		key: 'registrationManagement.enabled',
		group: 'Registration Management',
		label: 'Enable registration management (RFC 7592)',
		type: 'boolean',
		description: 'Enables update/delete for dynamically registered clients.'
	},
	{
		key: 'registrationManagement.rotateRegistrationAccessToken',
		group: 'Registration Management',
		label: 'Rotate registration access token',
		type: 'boolean',
		dependsOn: 'registrationManagement.enabled',
		description: 'Enables registration access token rotation.'
	},

	{
		key: 'conformIdTokenClaims',
		group: 'ID Token',
		label: 'Conform ID Token claims',
		type: 'boolean',
		description:
			'When on, an ID Token carries End-User claims only where the requested response_type is id_token. Turning it off includes scope-derived claims in ID Tokens issued from other response types. On by default (spec-conformant).'
	},

	{
		key: 'scopes',
		group: 'Discovery',
		label: 'Supported scopes',
		type: 'string-array',
		description: 'Scopes advertised in discovery. Must include openid.'
	},
	{
		key: 'acrValues',
		group: 'Discovery',
		label: 'Supported acr values',
		type: 'string-array',
		description: 'ACR values the server supports (acr_values_supported).'
	},
	{
		key: 'clientAuthMethods',
		group: 'Discovery',
		label: 'Client authentication methods',
		type: 'string-array',
		options: CLIENT_AUTH_METHODS,
		description:
			'token_endpoint_auth_methods_supported (mTLS methods added when enabled).'
	}
];
