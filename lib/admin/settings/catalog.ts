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

/*
 * Which pane of the console a setting appears on.
 *
 * A closed union rather than a free string, because the sub-nav is built from SETTING_DOMAINS below
 * and a typo would file a setting onto a pane that does not exist — reachable through the API and
 * invisible in the UI, which is the worst of both. test/admin/settings_metadata.spec.ts pins that
 * every declared domain holds at least one setting and every setting names a declared domain.
 */
export type SettingDomain =
	| 'grants'
	| 'request-security'
	| 'endpoints'
	| 'signin-abuse'
	| 'diagnostics'
	| 'integrations';

/*
 * The sub-nav, in order. Lives here rather than in the console so the panes cannot disagree with the
 * settings filed onto them: one list, read by both.
 */
export const SETTING_DOMAINS: {
	id: SettingDomain;
	label: string;
	blurb: string;
}[] = [
	{
		id: 'grants',
		label: 'Grants & flows',
		blurb: 'Which OAuth and OpenID flows this server issues tokens through.'
	},
	{
		id: 'request-security',
		label: 'Request security',
		blurb: 'How an authorization request is proven, bound and protected.'
	},
	{
		id: 'endpoints',
		label: 'Endpoints & discovery',
		blurb: 'Which protocol endpoints are served, and what discovery advertises.'
	},
	{
		id: 'signin-abuse',
		label: 'Sign-in & abuse',
		blurb: 'End-user sign-in, and the limits that keep it from being abused.'
	},
	{
		id: 'diagnostics',
		label: 'Diagnostics',
		blurb: 'What this server records when something fails, and where it goes.'
	},
	{
		id: 'integrations',
		label: 'Integrations',
		blurb: 'Outbound services, and machine access to this console.'
	}
];

export interface SettingDescriptor {
	key: keyof typeof ApplicationConfig;
	/* Which console pane this setting appears on. */
	domain: SettingDomain;
	/* The card this setting appears in, within its pane. */
	group: string;
	label: string;
	/*
	 * One line, shown beside the control while an operator is scanning. The `description` below is the
	 * long form, shown only once they stop on this row.
	 *
	 * The split exists because the descriptions here are genuinely long — several run past a hundred
	 * words, and rightly so — and rendering all of them at once made the prose most of the page. A
	 * bound on this field (100 characters, pinned by test) is what stops the two from collapsing back
	 * into one wall of text.
	 */
	summary: string;
	description: string;
	type: SettingType;
	options?: string[];
	/*
	 * The suffix rendered inside a numeric input: 'seconds', 'days', 'requests', 'faults'. Required on
	 * every `number` and refused on everything else.
	 *
	 * Deliberately a string and not a union. The vocabulary is one word per quantity and each is used
	 * once or twice, so a union would enumerate fourteen members to buy nothing — what matters is that
	 * a number never renders without a unit, and that is an invariant about presence, not spelling.
	 */
	unit?: string;
	dependsOn?: keyof typeof ApplicationConfig;
	/*
	 * Changing this setting has a security consequence in at least one direction, so the console tags
	 * it and makes saving it a confirmed action rather than a click.
	 *
	 * One value, not a taxonomy. "Weakens the server" and "incident kill switch" would render the same
	 * tag and require the same confirmation, and the difference between them is already explained in
	 * the descriptions — a second value would only be a thing to classify wrongly. The set of flagged
	 * keys is pinned by test/admin/settings_metadata.spec.ts, because a setting silently losing its
	 * flag is precisely the regression that matters here.
	 */
	risk?: 'security';
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
		domain: 'grants',
		group: 'Authorization',
		label: 'Allow omitting a single registered redirect_uri',
		summary:
			'Let a client with one registered redirect_uri omit it from requests',
		type: 'boolean',
		risk: 'security',
		description:
			'When a client has exactly one registered redirect_uri, allow authorization and token requests to omit redirect_uri and resolve it to that single value. Off by default (secure).'
	},

	{
		key: 'par.enabled',
		domain: 'request-security',
		group: 'PAR',
		label: 'Enable PAR (RFC 9126)',
		summary: 'Serve the pushed_authorization_request endpoint',
		type: 'boolean',
		description: 'Enables the pushed_authorization_request endpoint.'
	},
	{
		key: 'par.allowUnregisteredRedirectUris',
		domain: 'request-security',
		group: 'PAR',
		label: 'Allow unregistered redirect_uris via PAR',
		summary:
			'Let authenticated PAR clients use redirect_uris they never registered',
		type: 'boolean',
		dependsOn: 'par.enabled',
		risk: 'security',
		description:
			'Lets authenticated PAR clients use unregistered redirect_uri values (no sector_identifier_uri).'
	},

	{
		key: 'dpop.enabled',
		domain: 'request-security',
		group: 'DPoP',
		label: 'Enable DPoP (RFC 9449)',
		summary:
			'Sender-constrain tokens with application-layer proof-of-possession',
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
		domain: 'request-security',
		group: 'DPoP',
		label: 'Require DPoP nonce',
		summary: 'Require a server-issued nonce in every DPoP proof',
		type: 'boolean',
		dependsOn: 'dpop.enabled',
		description:
			'Requires a server-provided DPoP nonce. The secret the nonces are derived from is managed by the server; there is nothing to supply.'
	},
	/*
	 * `dpop.allowReplay` is deliberately absent, and this is the record of why.
	 *
	 * It disables DPoP proof replay detection: with it on, validateReplay skips the uniqueness check
	 * on the proof's `jti` entirely (helpers/validate_dpop.ts), so one proof can be presented any
	 * number of times. That removes the property DPoP exists to provide — an intercepted access token
	 * and proof become replayable — while discovery goes on advertising DPoP support.
	 *
	 * So there is no question an operator could answer to set it. Every direction of it removes a
	 * check, and the only callers that want it are a conformance suite replaying one proof on purpose
	 * and a person repeating a request while diagnosing something. Neither is administration, and
	 * neither reaches for a web console: both set it at startup.
	 *
	 * Hence boot configuration rather than a constant. The key stays in ApplicationConfig and
	 * validate_dpop.ts reads it unchanged, so those two uses still work and
	 * test/configuration/configuration.spec.ts still exercises both values. What its absence here
	 * removes is the console and the MCP surface: the admin PUT filters submissions against this
	 * catalog, so a key with no descriptor cannot be written through the API at all. Same technique,
	 * and the same reason, as `dpop.nonceSecret` above and `sentry.dsn` below.
	 *
	 * It was catalogued until the settings audit of 2026-09-02, where it was the one entry of
	 * sixty-two that failed the criterion recorded in sentry/dispatch.ts. Pinned in both directions by
	 * test/admin/settings_catalog.spec.ts.
	 */

	{
		key: 'introspection.enabled',
		domain: 'endpoints',
		group: 'Introspection',
		label: 'Enable Token Introspection (RFC 7662)',
		summary: 'Serve token introspection for opaque access and refresh tokens',
		type: 'boolean',
		description:
			'Enables introspection for opaque access tokens and refresh tokens.'
	},
	{
		key: 'jwtIntrospection.enabled',
		domain: 'endpoints',
		group: 'Introspection',
		label: 'JWT introspection responses (RFC 9701)',
		summary: 'Return introspection results as a signed JWT',
		type: 'boolean',
		dependsOn: 'introspection.enabled',
		description:
			'JWT responses for introspection. Requires Introspection enabled.'
	},

	{
		key: 'responseMode.jwt.enabled',
		domain: 'request-security',
		group: 'JWT Response Modes',
		label: 'Enable JARM',
		summary: 'Return authorization responses as a signed JWT (JARM)',
		type: 'boolean',
		description: 'Enables JWT Secured Authorization Responses.'
	},

	{
		key: 'fapi.enabled',
		domain: 'request-security',
		group: 'FAPI',
		label: 'Enable FAPI behaviours',
		summary:
			'Apply the extra Authorization Server behaviours of the FAPI profile',
		type: 'boolean',
		description:
			'Extra Authorization Server behaviours defined in the FAPI profile.'
	},

	{
		key: 'clientCredentials.enabled',
		domain: 'grants',
		group: 'Client Credentials',
		label: 'Enable client_credentials grant',
		summary: 'Accept grant_type=client_credentials at the token endpoint',
		type: 'boolean',
		description: 'Enables grant_type=client_credentials on the token endpoint.'
	},

	{
		key: 'backchannelLogout.enabled',
		domain: 'endpoints',
		group: 'Back-Channel Logout',
		label: 'Enable Back-Channel Logout',
		summary: 'Notify clients of sign-out over a back channel',
		type: 'boolean',
		description: 'Enables OIDC Back-Channel Logout features.'
	},

	{
		key: 'encryption.enabled',
		domain: 'request-security',
		group: 'Encryption',
		label: 'Enable encryption features',
		summary: 'Allow encrypted UserInfo, ID Tokens and Request Objects',
		type: 'boolean',
		description:
			'Encrypted UserInfo/ID Tokens and signed/encrypted Request Objects.'
	},

	{
		key: 'userinfo.enabled',
		domain: 'endpoints',
		group: 'UserInfo',
		label: 'Enable the UserInfo endpoint',
		summary: 'Serve the UserInfo endpoint',
		type: 'boolean',
		description: 'Enables the UserInfo endpoint.'
	},
	{
		key: 'jwtUserinfo.enabled',
		domain: 'endpoints',
		group: 'UserInfo',
		label: 'JWT UserInfo responses',
		summary: 'Return UserInfo as a signed JWT',
		type: 'boolean',
		dependsOn: 'userinfo.enabled',
		description: 'JWT responses for UserInfo. Requires UserInfo enabled.'
	},

	{
		key: 'revocation.enabled',
		domain: 'endpoints',
		group: 'Revocation',
		label: 'Enable Token Revocation (RFC 7009)',
		summary: 'Serve the token revocation endpoint',
		type: 'boolean',
		description: 'Enables Token Revocation.'
	},

	{
		key: 'rpInitiatedLogout.enabled',
		domain: 'endpoints',
		group: 'RP-Initiated Logout',
		label: 'Enable RP-Initiated Logout',
		summary: 'Let a client start sign-out and return the user to itself',
		type: 'boolean',
		description: 'Enables OIDC RP-Initiated Logout.'
	},

	{
		key: 'claimsParameter.enabled',
		domain: 'request-security',
		group: 'Claims Parameter',
		label: 'Enable the claims parameter',
		summary: 'Accept and validate the claims request parameter',
		type: 'boolean',
		description: 'Enables use and validation of the claims parameter.'
	},

	{
		key: 'mTLS.enabled',
		domain: 'request-security',
		group: 'mTLS',
		label: 'Enable mTLS features (RFC 8705)',
		summary: 'Authenticate clients by TLS certificate',
		type: 'boolean',
		description:
			'Enables Mutual TLS client authentication / certificate-bound tokens.'
	},
	{
		key: 'mTLS.certificateBoundAccessTokens',
		domain: 'request-security',
		group: 'mTLS',
		label: 'Certificate-bound access tokens',
		summary: 'Bind issued access tokens to the client certificate',
		type: 'boolean',
		dependsOn: 'mTLS.enabled',
		description: 'Requires mTLS enabled.'
	},
	{
		key: 'mTLS.selfSignedTlsClientAuth',
		domain: 'request-security',
		group: 'mTLS',
		label: 'self_signed_tls_client_auth method',
		summary: 'Accept the self_signed_tls_client_auth method',
		type: 'boolean',
		dependsOn: 'mTLS.enabled',
		description: 'Requires mTLS enabled.'
	},
	{
		key: 'mTLS.tlsClientAuth',
		domain: 'request-security',
		group: 'mTLS',
		label: 'tls_client_auth method',
		summary: 'Accept the tls_client_auth method',
		type: 'boolean',
		dependsOn: 'mTLS.enabled',
		description: 'Requires mTLS enabled.'
	},

	{
		key: 'deviceFlow.enabled',
		domain: 'grants',
		group: 'Device Flow',
		label: 'Enable Device Authorization Grant (RFC 8628)',
		summary:
			'Serve the device authorization grant for input-constrained devices',
		type: 'boolean',
		description: 'Enables the Device Authorization Grant.'
	},
	{
		key: 'deviceFlow.charset',
		domain: 'grants',
		group: 'Device Flow',
		label: 'User-code charset',
		summary: 'Which characters generated user codes are drawn from',
		type: 'enum',
		options: ['base-20', 'digits'],
		dependsOn: 'deviceFlow.enabled',
		description:
			'Character set for generated user codes. "digits" suits a device paired from a numeric keypad or a TV remote; "base-20" packs more entropy into the same number of characters.'
	},
	{
		key: 'deviceFlow.mask',
		domain: 'grants',
		group: 'Device Flow',
		label: 'User-code mask',
		summary: 'The shape of a generated user code',
		type: 'string',
		dependsOn: 'deviceFlow.enabled',
		description:
			'Template for user codes; * is replaced by a random charset char. Every * is one character of entropy, so shortening the template to spare the person typing it also shortens what an attacker has to guess.'
	},

	{
		key: 'ciba.enabled',
		domain: 'grants',
		group: 'CIBA',
		label: 'Enable CIBA flow',
		summary: 'Serve the client-initiated backchannel authentication flow',
		type: 'boolean',
		description: 'Enables Core CIBA flow.'
	},
	{
		key: 'ciba.deliveryModes',
		domain: 'grants',
		group: 'CIBA',
		label: 'Token delivery modes',
		summary: 'How a client collects a CIBA token once the user approves',
		type: 'string-array',
		options: ['poll', 'ping'],
		dependsOn: 'ciba.enabled',
		description: 'Supported CIBA token delivery modes.'
	},

	{
		key: 'requestObjects.enabled',
		domain: 'request-security',
		group: 'Request Objects',
		label: 'Enable Request Objects (JAR)',
		summary: 'Accept authorization parameters inside a signed request object',
		type: 'boolean',
		description: 'Enables the request (Request Object) parameter.'
	},
	{
		key: 'requestObjects.requireSignedRequestObject',
		domain: 'request-security',
		group: 'Request Objects',
		label: 'Require signed request objects',
		summary:
			'Refuse authorization requests that are not signed request objects',
		type: 'boolean',
		dependsOn: 'requestObjects.enabled',
		description:
			'Requires signed request objects for all authorization requests.'
	},

	{
		key: 'resourceIndicators.enabled',
		domain: 'request-security',
		group: 'Resource Indicators',
		label: 'Enable Resource Indicators (RFC 8707)',
		summary: 'Let a client name the resource server a token is meant for',
		type: 'boolean',
		description: 'Enables Resource Indicators features.'
	},

	{
		key: 'richAuthorizationRequests.enabled',
		domain: 'request-security',
		group: 'Rich Authorization Requests',
		label: 'Enable RAR (RFC 9396)',
		summary: 'Accept fine-grained authorization_details on a request',
		type: 'boolean',
		description:
			'Enables the authorization_details parameter, per RFC 9396 (published May 2023). Requires at least one authorization details type below, and requires Resource Indicators — details are only assigned to an access token bound to a resource server.'
	},
	{
		key: 'richAuthorizationRequests.types',
		domain: 'request-security',
		group: 'Rich Authorization Requests',
		label: 'Authorization details types',
		summary: 'The authorization details types this server accepts',
		type: 'json',
		dependsOn: 'richAuthorizationRequests.enabled',
		description:
			'The authorization details types this server accepts, as a map of type identifier to a descriptor: {"https://scheme.example/payment":{"label":"Initiate a payment","fields":{"actions":{"required":true,"allowed":["initiate"]}},"allowUnknownFields":false}}. `label` is what the consent screen shows. Constraints may only name the RFC 9396 §2 common fields (actions, locations, datatypes, privileges, identifier); `identifier` is single-valued so it takes `required` only. Unknown fields are refused unless a type opts in.'
	},

	{
		key: 'cors.enabled',
		domain: 'signin-abuse',
		group: 'CORS',
		label: 'Enable cross-origin access for browser clients',
		summary: 'Let browser apps read responses from this server',
		type: 'boolean',
		risk: 'security',
		description:
			'Lets browser-based apps read responses from the metadata and key endpoints, and from the endpoints listed on a project’s browser origins. Closure normally comes from data — a project with no origins grants nothing — so this is an incident kill switch rather than the usual control.'
	},

	{
		key: 'rateLimit.enabled',
		domain: 'signin-abuse',
		group: 'Rate limiting',
		label: 'Refuse a calling origin that exceeds its request allowance',
		summary: 'Refuse a caller that exceeds its request allowance',
		type: 'boolean',
		risk: 'security',
		description:
			'Refuses requests from one origin past its allowance inside a window, before the endpoint does any work. Allowances are tiered by route class, so the token endpoint and a static asset are not held to the same number. On by default; turn it off as an incident kill switch if it starts refusing traffic it should not. Applied at startup.'
	},
	{
		key: 'rateLimit.trustedProxy',
		domain: 'signin-abuse',
		group: 'Rate limiting',
		label: 'Take the caller’s address from the proxy headers',
		summary: 'Read the caller address from proxy headers',
		type: 'boolean',
		dependsOn: 'rateLimit.enabled',
		risk: 'security',
		description:
			'Whether Fly-Client-IP, the first hop of X-Forwarded-For, or X-Real-IP names the caller. This one has a wrong answer in each direction. Leave it ON when a proxy or load balancer sits in front of this server: with it off, every caller arrives as the proxy’s address, so the whole internet shares one allowance and all traffic is refused within seconds. Turn it OFF only when the server is directly exposed: with it on, any caller can set the header to a fresh value per request and is never limited. Defaults to on, matching the shipped deployment.'
	},
	{
		key: 'rateLimit.maxTrackedOrigins',
		domain: 'signin-abuse',
		group: 'Rate limiting',
		label: 'Origins remembered per route class',
		summary: 'How many callers each route class tracks at once',
		type: 'number',
		unit: 'origins',
		dependsOn: 'rateLimit.enabled',
		description:
			'How many distinct origins each class tracks at once, capping the limiter’s own memory. Bounded on purpose: the key comes from the caller, so an unbounded tally would itself become the memory-exhaustion vector this feature exists to prevent. Past the bound the least recently seen origin is forgotten and gets a fresh allowance. Lower it on a small machine.'
	},
	{
		key: 'rateLimit.strict.max',
		domain: 'signin-abuse',
		group: 'Rate limiting',
		label: 'Strict allowance — requests per window',
		summary: 'Allowance for token, authorization and other costly routes',
		type: 'number',
		unit: 'requests',
		dependsOn: 'rateLimit.enabled',
		description:
			'Applies to the unauthenticated and expensive surface: token issuance, authorization, dynamic registration, device and CIBA, and every end-user door that checks a secret or sends mail. Raise it if a legitimate server-to-server integration behind a single address, or many users behind one corporate NAT, start seeing refusals.'
	},
	{
		key: 'rateLimit.strict.windowSeconds',
		domain: 'signin-abuse',
		group: 'Rate limiting',
		label: 'Strict allowance — window length in seconds',
		summary: 'Window the strict allowance is measured over',
		type: 'number',
		unit: 'seconds',
		dependsOn: 'rateLimit.enabled',
		description:
			'The period the strict allowance is measured over. A caller timing requests around the boundary can send close to twice the allowance across two adjacent windows; that is normal for this kind of limit and not a defect.'
	},
	{
		key: 'rateLimit.ordinary.max',
		domain: 'signin-abuse',
		group: 'Rate limiting',
		label: 'Ordinary allowance — requests per window',
		summary: 'Allowance for userinfo, admin and other ordinary routes',
		type: 'number',
		unit: 'requests',
		dependsOn: 'rateLimit.enabled',
		description:
			'Applies to everything not classified strict or public: userinfo, introspection, revocation, the administration API, the MCP surface, and the rest of the end-user screens. Any endpoint added without an explicit classification lands here, so it is sized for a mixed session rather than for one endpoint.'
	},
	{
		key: 'rateLimit.ordinary.windowSeconds',
		domain: 'signin-abuse',
		group: 'Rate limiting',
		label: 'Ordinary allowance — window length in seconds',
		summary: 'Window the ordinary allowance is measured over',
		type: 'number',
		unit: 'seconds',
		dependsOn: 'rateLimit.enabled',
		description: 'The period the ordinary allowance is measured over.'
	},
	{
		key: 'rateLimit.public.max',
		domain: 'signin-abuse',
		group: 'Rate limiting',
		label: 'Public allowance — requests per window',
		summary: 'Allowance for assets, discovery and the key set',
		type: 'number',
		unit: 'requests',
		dependsOn: 'rateLimit.enabled',
		description:
			'Applies to the cheap public surface — static assets, the discovery document, the key set — and to every cross-origin preflight. Sized to clear the administration console’s full page-and-asset load from one address. Raise it if the console stutters while loading.'
	},
	{
		key: 'rateLimit.public.windowSeconds',
		domain: 'signin-abuse',
		group: 'Rate limiting',
		label: 'Public allowance — window length in seconds',
		summary: 'Window the public allowance is measured over',
		type: 'number',
		unit: 'seconds',
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
		domain: 'signin-abuse',
		group: 'Login throttle',
		label: 'Failed password attempts allowed per window',
		summary: 'Wrong passwords one address may try before sign-in shuts',
		type: 'number',
		unit: 'attempts',
		description:
			'How many wrong passwords one address may submit before the sign-in door shuts for that address. Once shut it refuses every attempt, including one with the correct password, until the window ends — and the refusal looks exactly like an ordinary wrong password, so it tells an attacker nothing. Raising this hands a guessing attack proportionally more tries; lowering it locks out people who mistype. Matches the verification code’s attempt cap by default. Applied at startup.'
	},
	{
		key: 'loginThrottle.windowSeconds',
		domain: 'signin-abuse',
		group: 'Login throttle',
		label: 'First lockout length in seconds',
		summary: 'How long sign-in shuts the first time an address runs out',
		type: 'number',
		unit: 'seconds',
		description:
			'How long the door stays shut the first time an address runs out of attempts, and the length each further lockout doubles from. This is also the shortest wait an honest user who trips the throttle will face, so it is the number to lower if legitimate lockouts are the complaint. A bucket that requires a one-time code stays at this length however often it is tripped, because a guessed password there does not sign anyone in. Applied at startup.'
	},
	{
		key: 'loginThrottle.windowCeilingSeconds',
		domain: 'signin-abuse',
		group: 'Login throttle',
		label: 'Longest lockout length in seconds',
		summary: 'The longest sign-in will ever shut for one address',
		type: 'number',
		unit: 'seconds',
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
		domain: 'signin-abuse',
		group: 'Federation',
		label: 'Enable sign-in through an upstream identity provider',
		summary: 'Let a bucket offer sign-in through an upstream provider',
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
		domain: 'integrations',
		group: 'Administration',
		label: 'Enable the administrative MCP control plane',
		summary: 'Let an AI agent administer this server over MCP',
		type: 'boolean',
		description:
			'Serves this control plane to an AI agent over MCP at /mcp, as an OAuth 2.1 protected resource of this server. An agent acts as the administrator who authorized it and gets exactly that account’s permissions: every operation runs through the same routes, the same checks and the same audit trail as the console, and each entry records both the operator and the agent. Deleting a project or a user bucket is withheld from agents entirely and stays console-only. Off by default — with it off, neither /mcp nor its metadata document is served. Applied at startup.'
	},

	{
		key: 'errorStore.enabled',
		domain: 'diagnostics',
		group: 'Error Store',
		label: 'Record internal server faults',
		summary: 'Keep a durable record of unexpected internal faults',
		type: 'boolean',
		description:
			'Keeps a durable record of unexpected internal faults so a failure can be diagnosed after it happened rather than only while it is happening. Routine client rejections — a bad grant, a wrong password, an expired code — are correct behaviour and are never recorded, so every entry is a defect. Off by default; with it off nothing is written and the /admin/api/errors paths are not served at all.'
	},
	{
		key: 'errorStore.retentionDays',
		domain: 'diagnostics',
		group: 'Error Store',
		label: 'Retention window (days)',
		summary: 'How long a recorded fault is kept',
		type: 'number',
		unit: 'days',
		dependsOn: 'errorStore.enabled',
		description:
			'How long a recorded fault is kept. The window runs from when the fault was last seen, not when it was first seen, so a fault that is still happening does not age out mid-life.'
	},
	{
		key: 'errorStore.maxGroups',
		domain: 'diagnostics',
		group: 'Error Store',
		label: 'Maximum distinct faults retained',
		summary: 'How many distinct faults are kept at once',
		type: 'number',
		unit: 'faults',
		dependsOn: 'errorStore.enabled',
		description:
			'How many distinct faults are kept. At the limit the least recently seen fault is evicted — never the oldest by creation, which would discard a long-running problem in favour of one that happened once this morning.'
	},
	{
		key: 'errorStore.samplesPerGroup',
		domain: 'diagnostics',
		group: 'Error Store',
		label: 'Occurrences kept per fault',
		summary: 'Full occurrences retained per distinct fault',
		type: 'number',
		unit: 'occurrences',
		dependsOn: 'errorStore.enabled',
		description:
			'How many full occurrences are retained for each distinct fault: the earliest, plus the most recent ones. The occurrence count stays exact however many are discarded — this bounds the detail kept, never the tally.'
	},
	{
		key: 'errorStore.queueDepth',
		domain: 'diagnostics',
		group: 'Error Store',
		label: 'Pending write queue depth',
		summary: 'How many records may await writing',
		type: 'number',
		unit: 'records',
		dependsOn: 'errorStore.enabled',
		description:
			'How many records may await writing. Recording never delays a response, so faults are queued rather than written inline — which makes this also the loss bound: an abruptly killed process can lose at most this many records, and a full queue counts what it could not accept so an operator can see that recording fell behind.'
	},
	{
		key: 'errorStore.originCaptureLevel',
		domain: 'diagnostics',
		group: 'Error Store',
		label: 'Caller address detail',
		summary: 'How much of the caller address a record keeps',
		type: 'enum',
		options: ['omitted', 'anonymized', 'full'],
		dependsOn: 'errorStore.enabled',
		description:
			'How much of the caller’s network address a record keeps, because an address is personal data. "omitted" stores none and says so; "anonymized" stores a value that cannot be reversed to the address but is still the same for two requests from one origin, so a single misbehaving deployment is still identifiable; "full" stores the address. Defaults to anonymized.'
	},

	/*
	 * `sentry.dsn` is deliberately absent, and this is the record of why.
	 *
	 * It is the ingestion credential of the receiving project, and this catalog is the read surface:
	 * `stateFor` builds the settings response by iterating these descriptors, so a key described here
	 * is a key returned to the console. The credential is write-only by requirement — a read reports
	 * whether one is stored and never what it is — so it is served by /admin/api/settings/sentry
	 * instead, and the generic PUT refuses it for free because it has no descriptor to validate
	 * against. Same technique, and same reason, as `dpop.nonceSecret` above.
	 */
	{
		key: 'sentry.enabled',
		domain: 'diagnostics',
		group: 'Error Store',
		label: 'Report recorded faults to Sentry',
		summary: 'Also send every recorded fault to a Sentry project',
		type: 'boolean',
		/*
		 * In the Error Store group rather than one of its own, because reporting genuinely requires
		 * recording — the outbound event is projected from the internal record, so there is nothing to
		 * report without one. Grouping it here makes `dependsOn` express that: the console cannot offer
		 * the toggle until the store is on, which is the order checkSentry enforces anyway. Filed under
		 * its own heading it read as an independent capability, and the first thing an operator learned
		 * otherwise was a refusal on save.
		 */
		dependsOn: 'errorStore.enabled',
		description:
			'Sends every fault the error store records to an external Sentry project, so a failure raises an alert instead of waiting to be found here. This is an additional destination, never an alternative: the fault is recorded locally first and the outbound event is built from that record, which is why this cannot be switched on unless the error store is. Only the endpoint, the kind of failure and the reference are sent — never a request URL, header, cookie, body, or any end-user identity. Off by default; requires the ingestion credential below. Applied at startup.'
	},
	/*
	 * `sentry.environment`, `sentry.release` and `sentry.queueDepth` are deliberately absent too, for
	 * a different reason than the credential: they are not secret, they are simply not the operator's
	 * to choose. The first two are facts about the deployment (NODE_ENV, the package version), so a
	 * field for either would only let the console and the deployment disagree. The queue depth is a
	 * rail against a pathological burst rather than a throughput knob, and there is no question an
	 * operator could answer to set it — sentry/dispatch.ts holds it as a constant and records why.
	 * The card reports all three read-only.
	 */

	{
		key: 'registration.enabled',
		domain: 'endpoints',
		group: 'Registration',
		label: 'Enable Dynamic Client Registration',
		summary: 'Let a client register itself at runtime',
		type: 'boolean',
		description: 'Enables Dynamic Client Registration.'
	},
	{
		key: 'registration.issueRegistrationAccessToken',
		domain: 'endpoints',
		group: 'Registration',
		label: 'Issue registration access token',
		summary: 'Issue a registration access token to a new client',
		type: 'boolean',
		dependsOn: 'registration.enabled',
		description: 'Whether a registration access token is issued.'
	},

	{
		key: 'registrationManagement.enabled',
		domain: 'endpoints',
		group: 'Registration Management',
		label: 'Enable registration management (RFC 7592)',
		summary: 'Let a registered client update or delete itself',
		type: 'boolean',
		description: 'Enables update/delete for dynamically registered clients.'
	},
	{
		key: 'registrationManagement.rotateRegistrationAccessToken',
		domain: 'endpoints',
		group: 'Registration Management',
		label: 'Rotate registration access token',
		summary: 'Issue a fresh registration access token on each update',
		type: 'boolean',
		dependsOn: 'registrationManagement.enabled',
		description: 'Enables registration access token rotation.'
	},

	{
		key: 'conformIdTokenClaims',
		domain: 'grants',
		group: 'ID Token',
		label: 'Conform ID Token claims',
		summary:
			'Carry end-user claims in an ID Token only where the spec requires',
		type: 'boolean',
		risk: 'security',
		description:
			'When on, an ID Token carries End-User claims only where the requested response_type is id_token. Turning it off includes scope-derived claims in ID Tokens issued from other response types. On by default (spec-conformant).'
	},

	{
		key: 'scopes',
		domain: 'endpoints',
		group: 'Discovery',
		label: 'Supported scopes',
		summary: 'Scopes advertised in discovery',
		type: 'string-array',
		description: 'Scopes advertised in discovery. Must include openid.'
	},
	{
		key: 'acrValues',
		domain: 'endpoints',
		group: 'Discovery',
		label: 'Supported acr values',
		summary: 'ACR values this server claims to support',
		type: 'string-array',
		description: 'ACR values the server supports (acr_values_supported).'
	},
	{
		key: 'clientAuthMethods',
		domain: 'endpoints',
		group: 'Discovery',
		label: 'Client authentication methods',
		summary: 'Client authentication methods advertised in discovery',
		type: 'string-array',
		options: CLIENT_AUTH_METHODS,
		description:
			'token_endpoint_auth_methods_supported (mTLS methods added when enabled).'
	}
];
