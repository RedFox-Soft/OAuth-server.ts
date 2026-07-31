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
	}
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
