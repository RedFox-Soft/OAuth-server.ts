import type { ApplicationConfigType } from 'lib/configs/application.js';
import { routeNames } from './param_list.js';

export type FeatureFlagKey = keyof ApplicationConfigType;

export interface GatedRoute {
	readonly method: string;
	readonly path: string;
	readonly flag: FeatureFlagKey;
}

export interface AlwaysAvailableRoute {
	readonly method: string;
	readonly path: string;
}

const clientConfiguration = `${routeNames.registration}/:clientId`;

/*
 * Paths are written in Elysia's declaration form so they compare directly against `elysia.routes`,
 * which is what lets the drift guard verify this table in both directions. Sourced from
 * `routeNames` wherever one exists so a path rename lands in a single place.
 *
 * Matching is exact on (method, path) — never a prefix test. `POST /token` is always available
 * while `POST /token/introspect` and `POST /token/revocation` are gated, so a `startsWith('/token')`
 * would take down every grant flow. The same trap sits under `/device` and `/reg`.
 */
export const gatedRoutes: readonly GatedRoute[] = [
	{
		method: 'POST',
		path: routeNames.pushed_authorization_request,
		flag: 'par.enabled'
	},
	{
		method: 'POST',
		path: routeNames.introspect,
		flag: 'introspection.enabled'
	},
	{ method: 'POST', path: routeNames.revocation, flag: 'revocation.enabled' },
	{
		method: 'POST',
		path: routeNames.registration,
		flag: 'registration.enabled'
	},
	// Reading one's own registration follows `registration`, not `registrationManagement`: the
	// registration response hands the client this URI, so refusing the read while registration is
	// on would break the capability that issued it. Management adds only the mutating methods.
	{ method: 'GET', path: clientConfiguration, flag: 'registration.enabled' },
	{
		method: 'PUT',
		path: clientConfiguration,
		flag: 'registrationManagement.enabled'
	},
	{
		method: 'DELETE',
		path: clientConfiguration,
		flag: 'registrationManagement.enabled'
	},
	{
		method: 'GET',
		path: routeNames.end_session,
		flag: 'rpInitiatedLogout.enabled'
	},
	{
		method: 'POST',
		path: routeNames.end_session_confirm,
		flag: 'rpInitiatedLogout.enabled'
	},
	{ method: 'GET', path: routeNames.userinfo, flag: 'userinfo.enabled' },
	{ method: 'POST', path: routeNames.userinfo, flag: 'userinfo.enabled' },
	{
		method: 'POST',
		path: routeNames.device_authorization,
		flag: 'deviceFlow.enabled'
	},
	{
		method: 'GET',
		path: routeNames.code_verification,
		flag: 'deviceFlow.enabled'
	},
	{
		method: 'POST',
		path: routeNames.code_verification,
		flag: 'deviceFlow.enabled'
	},
	{
		method: 'POST',
		path: routeNames.backchannel_authentication,
		flag: 'ciba.enabled'
	},

	/*
	 * The administrative MCP control plane, and the only gated routes whose subject is the admin plane
	 * rather than the OAuth surface.
	 *
	 * `/mcp` is gated rather than listed as always-available because the capability it exposes is
	 * administrative authority for an AI agent, and a deployment that has not switched it on must not
	 * serve it at all. Its metadata document is gated with it: RFC 9728 metadata describing an endpoint
	 * that is not served would advertise a resource a client then cannot reach, and leaving the document
	 * up while the endpoint is down is exactly the one-response fingerprint featureGate exists to avoid.
	 *
	 * Note these sit outside `/admin`, which is an alwaysAvailablePrefixes entry — the console itself is
	 * unconditional, and that asymmetry is deliberate: switching MCP off must not take the console with
	 * it (FR-030, FR-036).
	 */
	{ method: 'POST', path: routeNames.mcp, flag: 'mcp.enabled' },
	{ method: 'GET', path: routeNames.mcp, flag: 'mcp.enabled' },
	{ method: 'GET', path: routeNames.mcp_metadata, flag: 'mcp.enabled' },
	/*
	 * The three end-user legs of a federated sign-in — and the first gated routes to sit under `/ui`.
	 *
	 * That works because this table is consulted *before* alwaysAvailablePrefixes in both consumers
	 * (classifyRoutePattern and gatedFlagForRequest below). The prefix's comment — that the interaction
	 * surface is unconditional because a locked-out user cannot be asked to wait for a toggle — survives
	 * intact: with this flag off there is no provider button and nothing a user could have started, so these
	 * are paths that do not exist rather than paths closed mid-flow.
	 *
	 * The routes that *configure* providers are deliberately not here. They stay classified by the `/admin`
	 * prefix, so a provider can be prepared before the capability is switched on — and, the case that
	 * decides it, can still be deleted by a deployment that has just switched it off.
	 */
	{
		method: 'GET',
		path: '/ui/:uid/federation/:providerId/start',
		flag: 'federation.enabled'
	},
	{
		method: 'GET',
		path: '/ui/:uid/federation/complete',
		flag: 'federation.enabled'
	},
	{
		method: 'GET',
		path: '/federation/callback',
		flag: 'federation.enabled'
	}

	/*
	 * The error store's read surface is deliberately NOT here, though `errorStore.enabled` exists and it
	 * would be mechanically possible: gatedFlagForRequest consults only this table, so an exact `/admin`
	 * entry would win over the alwaysAvailablePrefixes entry.
	 *
	 * It must not, because the admin operation set is invariant under capability switches — the policy
	 * this table's `/admin` prefix encodes and `test/mcp/capability_invariance.spec.ts` enforces. Gating
	 * an admin path also splits the console from the agent surface, which re-dispatches into the same
	 * routes without this plugin: the console would see 404 while the agent saw 403 for the same call.
	 *
	 * So the capability is expressed in the payload instead. The route answers, and says whether
	 * recording is on — which is what keeps "nothing is being recorded" distinguishable from "nothing has
	 * failed" without hiding the endpoint.
	 */
];

/*
 * Unconditional by design. Enumerated rather than defaulted, so mounting a new protocol endpoint is
 * a deliberate choice between gating it and listing it here — and forgetting to choose fails the
 * drift guard instead of shipping an ungated endpoint.
 */
export const alwaysAvailableRoutes: readonly AlwaysAvailableRoute[] = [
	{ method: 'GET', path: '/health' },
	{ method: 'GET', path: '/.well-known/openid-configuration' },
	{ method: 'GET', path: routeNames.jwks },
	{ method: 'GET', path: routeNames.authorization },
	{ method: 'POST', path: routeNames.authorization },
	{ method: 'POST', path: routeNames.token }
];

/*
 * Whole subtrees that are unconditional as a matter of design. A bare `/admin` and a bare
 * `/verify-email` are both mounted alongside their deeper paths, so the prefix test has to accept
 * the prefix itself — `startsWith('/admin/')` alone would leave `GET /admin` unclassified.
 */
export const alwaysAvailablePrefixes: readonly string[] = [
	'/ui',
	'/verify-email',
	// Self-service password reset. Part of the end-user interaction surface, which is unconditional by
	// design: a user locked out of their account cannot be asked to wait for a capability toggle.
	'/reset-password',
	'/admin',
	'/public'
];

function matchesPrefix(path: string): boolean {
	return alwaysAvailablePrefixes.some(
		(prefix) => path === prefix || path.startsWith(`${prefix}/`)
	);
}

export type CorsClass = 'open' | 'client-based' | 'none';

export interface CorsRoute {
	readonly method: string;
	readonly path: string;
	readonly cors: CorsClass;
}

/*
 * Which routes a browser may read cross-origin, and on whose authority. Same declaration form and
 * same two-way drift guard as gatedRoutes above: only `open` and `client-based` are enumerated, and
 * everything else is `none` — but the guard asserts the enumerated set is exactly these eight, so a
 * new endpoint cannot become readable cross-origin without an explicit edit here.
 *
 * `open` echoes any Origin (the data is public to anyone who can issue a request). `client-based`
 * echoes only an Origin listed on the project owning the calling client.
 */
export const corsRoutes: readonly CorsRoute[] = [
	// OIDC Discovery 1.0 §4 and §3: a JavaScript client cannot know a deployment in advance, so it
	// has to be able to fetch the metadata and the keys before it knows anything else.
	{
		method: 'GET',
		path: '/.well-known/openid-configuration',
		cors: 'open'
	},
	{ method: 'GET', path: routeNames.jwks, cors: 'open' },

	{ method: 'POST', path: routeNames.token, cors: 'client-based' },
	{ method: 'GET', path: routeNames.userinfo, cors: 'client-based' },
	{ method: 'POST', path: routeNames.userinfo, cors: 'client-based' },
	{ method: 'POST', path: routeNames.revocation, cors: 'client-based' },
	{
		method: 'POST',
		path: routeNames.pushed_authorization_request,
		cors: 'client-based'
	},
	{
		method: 'POST',
		path: routeNames.device_authorization,
		cors: 'client-based'
	}
];

/*
 * Deliberate exclusions, recorded because Discovery §3's "and any other endpoints directly accessed
 * by Clients" could be read to include them:
 *
 * - `/auth` — the browser-based-apps BCP forbids CORS here, and a browser reaches it by navigation.
 * - `/reg` and `/reg/:clientId` — Discovery §3 names the DCR endpoint explicitly, but browser-side
 *   dynamic registration is not a flow this product supports. Revisit if it ever is.
 * - `/token/introspect` — called by resource servers, which are backends.
 * - `/backchannel` — CIBA is initiated by the client's backend by construction.
 * - `/device` (user-code verification) — reached by navigation, not by fetch.
 */
const corsClassByKey = new Map<string, CorsClass>(
	corsRoutes.map((route) => [`${route.method} ${route.path}`, route.cors])
);

export function corsClassForPattern(method: string, path: string): CorsClass {
	return corsClassByKey.get(`${method} ${path}`) ?? 'none';
}

/*
 * The methods a CORS-enabled path actually serves, for the preflight's Access-Control-Allow-Methods.
 * Derived from the same table rather than restated, so `/userinfo` cannot advertise a method it does
 * not implement.
 */
export function corsMethodsForPath(path: string): string[] {
	return corsRoutes
		.filter((route) => route.path === path)
		.map((route) => route.method);
}

/*
 * Resolves an incoming request path to its CORS class, matching the way gatedFlagForRequest does
 * (segment-wise, so a `:param` consumes exactly one segment). Returns the class and the declared
 * pattern, because the preflight needs the pattern to look the served methods up.
 */
export function corsRouteForRequest(
	pathname: string
): { readonly path: string; readonly cors: CorsClass } | undefined {
	for (const route of corsRoutes) {
		if (patternMatchesPath(route.path, pathname)) {
			return { path: route.path, cors: route.cors };
		}
	}
	return undefined;
}

export type RateClass = 'strict' | 'ordinary' | 'public' | 'exempt';

export interface RateRoute {
	readonly method: string;
	readonly path: string;
	readonly rate: RateClass;
}

export interface RatePrefix {
	readonly prefix: string;
	readonly rate: RateClass;
}

/*
 * How much traffic one origin may direct at a route before the per-origin limiter refuses it. The
 * third classification dimension over this same route set, declared the same way as the two above and
 * under the same two-way drift guard.
 *
 * WHY tiers rather than one blanket number. A single allowance tight enough to protect the token
 * endpoint refuses the admin console's asset burst; one loose enough for the assets barely protects
 * the token endpoint. The two cannot be reconciled by choosing a middle value — they are two different
 * questions about two different costs.
 *
 * WHY `ordinary` is the default rather than an unclassified-route failure, which is the opposite of
 * what gatedRoutes does. A route nobody classified must still be *limited*: making omission mean
 * "unlimited" would turn forgetting this table into opting out of protection, silently. The drift
 * guard still pins the three enumerated classes exactly, so the decision cannot be skipped — it just
 * fails in the direction of more protection rather than less.
 *
 * Only the non-ordinary routes are enumerated, for the same reason corsRoutes enumerates only the two
 * permissive classes: the list that must be read carefully is the short one.
 */
export const rateRoutes: readonly RateRoute[] = [
	/*
	 * The platform probes this every 30 seconds (fly.toml). A refused health check is read by the proxy
	 * as an unhealthy machine and takes it out of rotation — the limiter causing the outage it exists to
	 * prevent. Exempt rather than merely generous, because no allowance is high enough to be safe here.
	 */
	{ method: 'GET', path: '/health', rate: 'exempt' },

	/*
	 * Strict: unauthenticated, or expensive, or both. Everything an attacker can make the server do real
	 * work for without first proving anything — a signature, a password hash, an account write.
	 */
	{ method: 'POST', path: routeNames.token, rate: 'strict' },
	{ method: 'GET', path: routeNames.authorization, rate: 'strict' },
	{ method: 'POST', path: routeNames.authorization, rate: 'strict' },
	{
		method: 'POST',
		path: routeNames.pushed_authorization_request,
		rate: 'strict'
	},
	{ method: 'POST', path: routeNames.registration, rate: 'strict' },
	{
		method: 'POST',
		path: routeNames.backchannel_authentication,
		rate: 'strict'
	},
	{ method: 'POST', path: routeNames.device_authorization, rate: 'strict' },
	// User-code verification: a short, human-typed code is guessable by volume alone.
	{ method: 'GET', path: routeNames.code_verification, rate: 'strict' },
	{ method: 'POST', path: routeNames.code_verification, rate: 'strict' },
	// Every end-user door that verifies a secret or sends mail. Each already carries a per-identity
	// throttle; this is the origin-level layer in front of it, and neither replaces the other.
	{ method: 'POST', path: '/ui/:uid/login', rate: 'strict' },
	{ method: 'POST', path: '/ui/:uid/registration', rate: 'strict' },
	{ method: 'POST', path: '/ui/:uid/forgot-password', rate: 'strict' },
	{ method: 'POST', path: '/ui/:uid/totp', rate: 'strict' },
	{ method: 'POST', path: '/ui/:uid/totp/enroll', rate: 'strict' },
	{ method: 'POST', path: '/verify-email/code', rate: 'strict' },
	{ method: 'POST', path: '/verify-email/resend', rate: 'strict' },
	{ method: 'POST', path: '/reset-password', rate: 'strict' },
	/*
	 * The two admin routes that are not ordinary. Both are unauthenticated by construction — one is how
	 * the first super-admin comes to exist, the other is how somebody invited into a group accepts —
	 * so they are the admin doors an attacker can knock on freely.
	 *
	 * The invitation token is 256 bits of randomness looked up by digest, so guessing one is not the
	 * threat; the cost of the account write behind it is, and that is what an origin limit bounds.
	 */
	{ method: 'POST', path: '/admin/api/setup', rate: 'strict' },
	{ method: 'POST', path: '/admin/api/invitations/accept', rate: 'strict' },

	/*
	 * Public: cheap, cacheable, and fetched by every client before it knows anything else about the
	 * deployment. Limiting these tightly would break discovery for a whole NAT before it protected
	 * anything — the response is a static document either way.
	 */
	{
		method: 'GET',
		path: '/.well-known/openid-configuration',
		rate: 'public'
	},
	{ method: 'GET', path: routeNames.mcp_metadata, rate: 'public' },
	{ method: 'GET', path: routeNames.jwks, rate: 'public' },
	{ method: 'GET', path: '/public/*', rate: 'public' }
];

/*
 * Prefix rules for the request-level resolver. `/public/*` is one mounted route but arrives as
 * `/public/admin.js`, and patternMatchesPath compares segment-wise against `:param` — it has no
 * wildcard case, deliberately. A prefix entry is how a wildcard mount is resolved without teaching
 * that function a second matching language.
 */
export const ratePrefixes: readonly RatePrefix[] = [
	{ prefix: '/public', rate: 'public' }
];

const rateClassByKey = new Map<string, RateClass>(
	rateRoutes.map((route) => [`${route.method} ${route.path}`, route.rate])
);

/*
 * Compares a route *pattern* against the table, for the drift guard. Never returns undefined: an
 * unenumerated route is `ordinary`, which is the whole point of the default documented above.
 */
export function rateClassForPattern(method: string, path: string): RateClass {
	const exact = rateClassByKey.get(`${method} ${path}`);
	if (exact !== undefined) {
		return exact;
	}
	for (const entry of ratePrefixes) {
		if (path === entry.prefix || path.startsWith(`${entry.prefix}/`)) {
			return entry.rate;
		}
	}
	return 'ordinary';
}

/*
 * Resolves an incoming request to its allowance class. Called on every request ahead of routing, so it
 * stays allocation-light and returns on the first match.
 */
export function rateClassForRequest(
	method: string,
	pathname: string
): RateClass {
	/*
	 * Checked before the table, and on the method alone. A preflight never reaches the route table —
	 * corsPreflight answers it by short-circuiting onRequest — and it costs almost nothing to answer.
	 * Charging one to the class of the request it precedes would halve a browser client's real
	 * allowance and refuse it for requests it never actually sent.
	 */
	if (method === 'OPTIONS') {
		return 'public';
	}

	for (const route of rateRoutes) {
		if (route.method === method && patternMatchesPath(route.path, pathname)) {
			return route.rate;
		}
	}
	for (const entry of ratePrefixes) {
		if (pathname === entry.prefix || pathname.startsWith(`${entry.prefix}/`)) {
			return entry.rate;
		}
	}
	return 'ordinary';
}

/*
 * Compares a route *pattern* (as Elysia declares it) against the table. Used by the drift guard,
 * which asks "is this mounted route classified?" — not by the request path, which needs
 * gatedFlagForRequest below.
 */
export function classifyRoutePattern(
	method: string,
	path: string
): 'gated' | 'always' | undefined {
	if (gatedRoutes.some((r) => r.method === method && r.path === path)) {
		return 'gated';
	}
	if (
		alwaysAvailableRoutes.some((r) => r.method === method && r.path === path) ||
		matchesPrefix(path)
	) {
		return 'always';
	}
	return undefined;
}

/*
 * Segment-wise comparison rather than a prefix or regex test: a `:param` consumes exactly one
 * segment, so `/reg/:clientId` matches `/reg/abc` and nothing deeper. A future
 * `/reg/:clientId/secret` therefore cannot be swept in by an existing entry.
 */
function patternMatchesPath(pattern: string, pathname: string): boolean {
	if (pattern === pathname) {
		return true;
	}
	if (!pattern.includes(':')) {
		return false;
	}

	const patternSegments = pattern.split('/');
	const pathSegments = pathname.split('/');
	if (patternSegments.length !== pathSegments.length) {
		return false;
	}

	return patternSegments.every((segment, i) => {
		const actual = pathSegments[i];
		if (actual === undefined) {
			return false;
		}
		return (segment.startsWith(':') && actual.length > 0) || segment === actual;
	});
}

/*
 * Resolves an incoming request to the flag governing it, or undefined when the request is not for a
 * gated route. Called on every request, so it stays allocation-light for the common miss.
 */
export function gatedFlagForRequest(
	method: string,
	pathname: string
): FeatureFlagKey | undefined {
	for (const route of gatedRoutes) {
		if (route.method === method && patternMatchesPath(route.path, pathname)) {
			return route.flag;
		}
	}
	return undefined;
}
