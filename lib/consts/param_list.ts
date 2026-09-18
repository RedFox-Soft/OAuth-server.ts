import { t } from 'elysia';
import { addressOf, type RequestBucket } from '../configs/issuer.js';

/**
 * A parameter this server refuses rather than ignores.
 *
 * Endpoints taking authorization-request parameters ignore what they do not recognize (RFC 6749
 * §3.1/§3.2, RFC 8628 §3.1, CIBA §7.1, and RFC 9126 §2.1 by reference). That makes *absence from a
 * schema* mean "ignore", so a parameter a specification tells this server to reject has to be
 * declared and typed as absent — otherwise the rejection silently becomes an acceptance.
 */
export const refusedParam = (name: string) =>
	t.Optional(
		t.Undefined({ error: `Property '${name}' should not be provided` })
	);

/*
 * The top-level members of the `claims` request value that this server understands. Declared as its
 * own object so the schema below and the filter in checkClaims read the same source: the set of
 * names that must survive cannot drift from the set the schema validates.
 */
const claimsMembers = {
	id_token: t.Optional(
		t.Object({}, { error: 'claims.id_token must be an object' })
	),
	userinfo: t.Optional(
		t.Object({}, { error: 'claims.userinfo must be an object' })
	)
};

export const CLAIMS_MEMBERS: ReadonlySet<string> = new Set(
	Object.keys(claimsMembers)
);

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
	registration: t.Optional(
		t.Undefined({
			error: {
				error: 'not_supported',
				error_description: 'Registration is not supported'
			}
		})
	),
	request: t.Optional(t.String()),
	request_uri: t.Optional(t.String({ format: 'uri' })),
	ui_locales: t.Optional(t.Array(t.String())),
	acr_values: t.Optional(t.String()),

	// added conditionally depending on feature flag which will be checked in the code
	claims: t.Optional(
		t.ObjectString(claimsMembers, {
			/*
			 * No `additionalProperties: false`. OIDC Core §5.5: "Other members MAY be present. Any
			 * members used that are not understood MUST be ignored." A closed object turns that
			 * permission into invalid_request — the same defect the endpoints themselves were fixed
			 * for in 1437341, one level in, inside a parameter's value rather than beside it.
			 * checkClaims deletes the undeclared members; see [[unknown-request-parameters]].
			 */
			error: 'claims parameter must be a JSON object'
		})
	),
	resource: t.Optional(t.Array(t.String())),
	/*
	 * The declared member shape is a runtime coercion contract, not just documentation: Elysia parses
	 * a JSON query value against it before any of our code runs. `t.Object({})` strips every member
	 * field, so `type` and the common fields arrive gone; `t.Array(t.Unknown())` splits the raw JSON
	 * string on its commas. Only an object that admits additional properties survives — measured, see
	 * specs/015-rar-end-to-end/research.md B3.
	 */
	authorization_details: t.Optional(
		t.Array(t.Object({}, { additionalProperties: true }))
	),
	dpop_jkt: t.Optional(t.String())
});

export const DeviceAuthorizationParameters = t.Partial(
	t.Omit(AuthorizationParameters, [
		'response_type',
		'response_mode',
		'code_challenge_method',
		'code_challenge',
		'state',
		'redirect_uri',
		'prompt',
		'request_uri'
	])
);

export const JWTparameters = t.Object({
	jti: t.String(),
	iss: t.String(),
	aud: t.String({ format: 'uri' }),
	exp: t.Integer({ minimum: 0 }),
	iat: t.Optional(t.Integer({ minimum: 0 })),
	nbf: t.Optional(t.Integer({ minimum: 0 }))
});

export const BackchannelAuthParameters = t.Object({
	...DeviceAuthorizationParameters.properties,
	client_notification_token: t.Optional(t.String()),
	login_hint_token: t.Optional(t.String()),
	binding_message: t.Optional(t.String()),
	user_code: t.Optional(t.String()),
	request_context: t.Optional(t.String()),
	requested_expiry: t.Optional(
		t.Integer({
			minimum: 0,
			error: 'requested_expiry must be a positive integer'
		})
	)
});

export const routeNames = {
	authorization: '/auth',
	backchannel_authentication: '/backchannel',
	code_verification: '/device',
	device_authorization: '/device/auth',
	end_session: '/logout',
	end_session_confirm: '/logout/confirm',
	introspect: '/token/introspect',
	jwks: '/jwks',
	mcp: '/mcp',
	/*
	 * RFC 9728 protected resource metadata for the MCP endpoint above. The well-known path is
	 * path-aware: the resource's own path is appended, so a resource at `/mcp` publishes at
	 * `/.well-known/oauth-protected-resource/mcp` rather than at the bare well-known root.
	 */
	mcp_metadata: '/.well-known/oauth-protected-resource/mcp',
	pushed_authorization_request: '/par',
	registration: '/reg',
	revocation: '/token/revocation',
	token: '/token',
	userinfo: '/userinfo'
} as const;

/* The default bucket's name in a cookie. It has none in its address, and a cookie name cannot be
 * empty; `default` is on the reserved list precisely so no bucket can collide with it. */
const DEFAULT_BUCKET_SLUG = 'default';

export const cookieNames = {
	interaction: '_interaction',
	session: '_session'
};

/*
 * The name of a bucket's session cookie, and the only place that answer is produced.
 *
 * Two sign-ins in one browser are two cookies, which is what lets an end user hold one in each of two
 * buckets without either disturbing the other. Before this, one name meant one cookie: signing in to a
 * second bucket overwrote the first bucket's sign-in, and the end user was silently signed out of an
 * application they had not touched.
 *
 * The bucket's public name, not its record id: it is already in the address bar, and the slug charset
 * (lowercase ASCII, digits, hyphen) is a valid cookie name as it stands. The default bucket has no
 * name in its address but has one here, because a cookie name cannot be empty — `default` is on the
 * reserved list precisely so no bucket can collide with it.
 *
 * Used to write the cookie *and* to build the cookie that clears it. A clear only removes a cookie
 * when it names the same one, so a second hand-written literal would clear a name the browser is not
 * holding while reporting success — the failure `cookie-path-scoping` exists to forbid, one attribute
 * over. It lives here, beside the name it extends and in a module neither the request pipeline nor the
 * models can cycle through, because both of them need it.
 */
export function sessionCookieName(bucket: RequestBucket): string {
	/*
	 * Switched on the bucket's *address*, not on whether it holds a slug, and the difference is
	 * load-bearing now that two kinds of bucket hold none.
	 *
	 * A bucket with no address of its own uses the bare endpoints — the ones its clients used before
	 * buckets became tenants — and shares the default bucket's cookie, exactly as it shares its
	 * behaviour. Falling back to the record id instead would name a cookie nobody reads: the sign-in
	 * screen knows which bucket the client belongs to and would write `_session_<id>`, while the bare
	 * `/auth` and `/logout` know only the address and would look for `_session_default`. The sign-in
	 * would complete and then not exist.
	 *
	 * A host-addressed bucket also holds no slug and must NOT reach that branch: it has an address, just
	 * not a path one. It needs no distinguishing name either. The suffix exists because path-addressed
	 * buckets share one origin — "two sign-ins in one browser are two cookies" — and a bucket on its own
	 * origin already has its cookie kept apart by the browser, since nothing here sets a domain
	 * attribute. A suffix would distinguish what is already distinct.
	 */
	const address = addressOf(bucket);
	switch (address.kind) {
		case 'host':
			return cookieNames.session;
		case 'path':
			return `${cookieNames.session}_${address.segment}`;
		case 'root':
		case 'unaddressed':
			return `${cookieNames.session}_${bucket.slug ?? DEFAULT_BUCKET_SLUG}`;
	}
}

/*
 * The attributes both end-user cookies are written with, wherever they are written.
 *
 * Shared rather than inlined because there is more than one cookie schema naming these cookies: the
 * `/ui/*` guard (lib/interactions/index.ts) declares its own `t.Cookie`, and Elysia merges a schema's
 * option object into every `cookie.set()` on the routes it guards — so a second literal is a second
 * policy. It drifted exactly that way: the `/ui` schema carried no options at all, and the login POST
 * writes `_session` through it, which is the moment the *authenticated* cookie is first issued.
 *
 * `secure` is the actual defense against the cookie travelling in cleartext; a proxy-level HTTPS
 * redirect (fly.toml `force_https`) only mitigates it.
 *
 * `lax` is not a weakening, and `strict` here broke every sign-in that actually started at a relying
 * party. A strict cookie is withheld on a cross-site-initiated top-level navigation — which is the
 * shape of the *whole* flow: the RP navigates the browser to `/auth`, which sets `_interaction` and
 * redirects to `/ui/${uid}/login`, whose guard requires it. The cookie arrived bare and the guard
 * answered 422 `Invalid interaction cookie`. It only ever worked when the navigation was
 * browser-initiated — typing the URL or reloading it, which counts as same-site — so a manual reload
 * of the failing URL returned 200 and hid the defect from every hand-driven reproduction.
 *
 * `_session` has the same requirement for a different outcome: withheld at `/auth`, an established
 * session is invisible, so a second RP silently re-prompts a user who is already signed in.
 *
 * What `lax` still refuses is the boundary that carries the CSRF property: cross-site POSTs and
 * cross-site subresource requests. Every form on these screens posts same-site to a page this server
 * served, so none of them depends on `strict`. The admin console cookie is a separate constant and
 * stays `strict` (lib/admin/auth/session.ts) — nothing legitimately navigates to `/admin` from
 * another site.
 */
export const endUserCookieAttributes = {
	httpOnly: true,
	sameSite: 'lax',
	secure: true
} as const;

export const AuthorizationCookies = t.Cookie(
	{
		_interaction: t.Optional(t.String()),
		_session: t.Optional(t.String())
	},
	endUserCookieAttributes
);
