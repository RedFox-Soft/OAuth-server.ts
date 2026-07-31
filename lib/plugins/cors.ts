import type { Elysia } from 'elysia';

import { ApplicationConfig } from 'lib/configs/application.js';
import { isOriginAllowed } from 'lib/helpers/cors_origin.js';
import { getProjectStore } from 'lib/adapters/index.js';
import { AccessToken } from 'lib/models/access_token.js';
import {
	corsMethodsForPath,
	corsRouteForRequest,
	gatedFlagForRequest
} from 'lib/consts/route_classification.js';

/*
 * Cross-Origin Resource Sharing, in three plugins:
 *
 *   corsOpen            — mounted in discovery and jwks; echoes any Origin.
 *   corsClientBased(fn) — mounted in token, userinfo, revocation, par and deviceAuth; echoes an
 *                         Origin only when it is listed on the project owning the calling client.
 *   corsPreflight       — mounted once in lib/index.ts; answers OPTIONS for both classes.
 *
 * Route classes live in lib/consts/route_classification.ts beside the feature-gate table, under the
 * same two-way drift guard.
 *
 * WHY onTransform and not onBeforeHandle. Elysia's order is Request → Parse → Transform → Validation
 * → BeforeHandle → Handle. Client authentication happens in AuthPlugin's `derive`, which runs in the
 * transform queue and throws `invalid_client` from there; body-schema failures raise a 422 in the
 * validation stage right after. Both precede beforeHandle, so a header written there would be absent
 * from exactly the responses a misconfigured browser app hits most — the 401 and the 422. Writing at
 * transform puts it ahead of both, and `set.headers` survives onto the error response because the
 * global handler mutates `set` rather than building its own Response (lib/shared/authorization_error_handler.ts).
 * The same merge carries the header onto handlers that return a raw Response, e.g. jwks.
 *
 * These plugins are callback-shaped (the lib/plugins/noCache.ts form) rather than standalone Elysia
 * instances. A callback receives the caller's instance, so the hook is inlined there and applies to
 * that instance's routes and descendants only — no `as: 'scoped'` reasoning, and no way for a header
 * to leak onto a sibling route. It does mean **registration order matters**: a hook only affects
 * routes declared after it, so every `.use(...)` below must precede the route it protects.
 *
 * ACCEPTED CONSEQUENCE. When no client can be identified — no client_id, an unparseable Basic header,
 * an unknown or expired access token — no header is emitted. A browser SPA carrying the wrong
 * client_id therefore sees an opaque network failure rather than the OAuth error body. That is the
 * price of not defaulting to open, and a deliberate departure from the previous (unreachable)
 * implementation, which fell open whenever no client resolved.
 */

/*
 * Read flat off ApplicationConfig per request rather than captured at boot, for the same reason
 * featureGate does it: settings are applied by restart in a deployment, but the test suite drives one
 * long-lived instance and flips them between cases.
 */
function corsEnabled(): boolean {
	return ApplicationConfig['cors.enabled'] === true;
}

type HeaderBag = Record<string, string | number | undefined>;

/*
 * Declared on every response this layer touches, echo or no echo. A shared cache that ignored it
 * could hand one origin's response — including a header-less one — to a different origin.
 */
function markVaryByOrigin(headers: HeaderBag): void {
	headers['Vary'] = 'Origin';
}

function allowOrigin(headers: HeaderBag, origin: string): void {
	// Echoed rather than `*`: one code path for both classes, and `*` would also forbid the
	// credentialed requests some deployments proxy. `Access-Control-Allow-Credentials` is never sent —
	// no endpoint in either class authenticates by cookie.
	headers['Access-Control-Allow-Origin'] = origin;
}

export const corsOpen = (app: Elysia) =>
	app.onTransform(({ request, set }) => {
		if (!corsEnabled()) {
			return;
		}

		markVaryByOrigin(set.headers);

		const origin = request.headers.get('origin');
		if (!origin) {
			return;
		}

		allowOrigin(set.headers, origin);
	});

/*
 * RFC 9449 §7.1 and §8: a browser can only read CORS-safelisted response headers, so without these
 * two names a browser client cannot see the DPoP nonce challenge and can never perform the retry the
 * spec requires of it. `WWW-Authenticate` is here for the same reason — the challenge is unreadable
 * otherwise. Fixed per route class rather than per response: the header list has to be stable, and a
 * client cannot ask for it conditionally.
 */
const EXPOSED_HEADERS = 'WWW-Authenticate, DPoP-Nonce';

/*
 * Resolves the client id from a request, or undefined when no client can be identified. Must never
 * throw: this runs from a hook whose only job is to add a header, so a malformed credential has to
 * mean "no header" and leave the endpoint free to reject the request on its own terms.
 */
export type ClientIdExtractor = (ctx: {
	readonly request: Request;
	readonly body: unknown;
}) => string | undefined | Promise<string | undefined>;

function basicAuthClientId(request: Request): string | undefined {
	const header = request.headers.get('authorization');
	if (!header) {
		return undefined;
	}

	const [scheme, value] = header.split(' ');
	if (scheme?.toLowerCase() !== 'basic' || !value) {
		return undefined;
	}

	try {
		const decoded = Buffer.from(value, 'base64').toString('utf8');
		const separator = decoded.indexOf(':');
		const id = separator === -1 ? decoded : decoded.slice(0, separator);
		// RFC 6749 §2.3.1 form-encodes the credentials before base64.
		return id ? decodeURIComponent(id) : undefined;
	} catch {
		return undefined;
	}
}

/*
 * The form endpoints: /token, /token/revocation, /par, /device/auth. `client_id` in the body first,
 * then the username half of a Basic header.
 *
 * A client authenticating only by `client_assertion` (private_key_jwt, client_secret_jwt) is
 * deliberately NOT decoded to find its id: a browser public client cannot hold a signing key, so the
 * case is theoretical, and parsing an unverified assertion in a header-setting hook would be a poor
 * trade. Such a client simply gets no CORS header.
 */
export const formClientId: ClientIdExtractor = ({ request, body }) => {
	if (body && typeof body === 'object' && !Array.isArray(body)) {
		const candidate = (body as Record<string, unknown>).client_id;
		if (typeof candidate === 'string' && candidate.length > 0) {
			return candidate;
		}
	}

	return basicAuthClientId(request);
};

/*
 * /userinfo, where the caller is identified by the access token it presents rather than by a
 * credential. Parsed here rather than through OIDCContext.getAccessToken because that helper throws
 * on a malformed header (by design — it is enforcing the endpoint's contract), and this hook must not.
 *
 * Costs one store read, incurred only when an Origin header is present — i.e. only for browser
 * traffic. The handler performs the same lookup moments later.
 */
export const accessTokenClientId: ClientIdExtractor = async ({ request }) => {
	const header = request.headers.get('authorization');
	if (!header) {
		return undefined;
	}

	const [scheme, value] = header.split(' ');
	if (!value || !['bearer', 'dpop'].includes(scheme?.toLowerCase() ?? '')) {
		return undefined;
	}

	// tryFind rather than find: an unknown or expired token means "no client", not an exception.
	const token = await AccessToken.tryFind(value);
	return token?.payload.clientId;
};

export const corsClientBased =
	(extractClientId: ClientIdExtractor) => (app: Elysia) =>
		app.onTransform(async ({ request, body, set }) => {
			if (!corsEnabled()) {
				return;
			}

			markVaryByOrigin(set.headers);

			const origin = request.headers.get('origin');
			if (!origin) {
				return;
			}

			const clientId = await extractClientId({ request, body });
			if (!clientId) {
				return;
			}

			const project = await getProjectStore().findByClientId(clientId);
			if (!isOriginAllowed(origin, project?.corsOrigins)) {
				return;
			}

			allowOrigin(set.headers, origin);
			set.headers['Access-Control-Expose-Headers'] = EXPOSED_HEADERS;
		});

/*
 * How long a browser may cache a preflight result. A module constant rather than a setting: the useful
 * range is dictated by browser behaviour, not by deployment, and it would be the first numeric key in
 * ApplicationConfig — which the admin settings catalog has no type for, so it would be uneditable and
 * therefore pointless. A `number` SettingType would make it a viable follow-up.
 */
const MAX_AGE = '3600';

/*
 * Avoids constructing a URL on every request to the server. Mirrors lib/plugins/featureGate.ts, for the
 * same reason: this runs on the hot path for all traffic, not just browser traffic.
 */
function pathnameOf(url: string): string {
	const start = url.indexOf('/', url.indexOf('://') + 3);
	if (start === -1) {
		return '/';
	}
	const query = url.indexOf('?', start);
	return query === -1 ? url.slice(start) : url.slice(start, query);
}

/*
 * Answers CORS preflights, and only those. Mounted once in lib/index.ts immediately after featureGate.
 *
 * Mount order is load-bearing twice over. onRequest hooks run in registration order and a
 * short-circuit ends the chain, so answering before `nocache` would omit the `Cache-Control: no-store`
 * every other response on this server carries — a one-header fingerprint distinguishing a 204 here from
 * every other reply. Answering before `featureGate` would be worse: a preflight would confirm an
 * endpoint that 404s every real request.
 *
 * The flag check below is what makes the second guarantee hold. gatedFlagForRequest matches exactly on
 * (method, path), so `OPTIONS /par` can never match the `POST /par` entry — the *requested* method has
 * to be substituted, or the lookup silently returns undefined and the gate is bypassed.
 */
export const corsPreflight = (app: Elysia) =>
	app.onRequest(({ request, set }) => {
		if (request.method !== 'OPTIONS' || !corsEnabled()) {
			return;
		}

		const origin = request.headers.get('origin');
		const requestedMethod = request.headers.get(
			'access-control-request-method'
		);
		// Both are mandatory in a preflight (Fetch §3.2.2). Without them this is an ordinary OPTIONS,
		// which no route serves — so it falls through to the same 404 as an unmounted path.
		if (!origin || !requestedMethod) {
			return;
		}

		const path = pathnameOf(request.url);
		const route = corsRouteForRequest(path);
		if (!route || route.cors === 'none') {
			return;
		}

		const flag = gatedFlagForRequest(requestedMethod, path);
		if (flag !== undefined && !ApplicationConfig[flag]) {
			return;
		}

		markVaryByOrigin(set.headers);
		allowOrigin(set.headers, origin);
		// Advertised from the classification table so a path cannot claim a method it does not serve.
		set.headers['Access-Control-Allow-Methods'] = corsMethodsForPath(
			route.path
		).join(', ');
		set.headers['Access-Control-Max-Age'] = MAX_AGE;

		const requestedHeaders = request.headers.get(
			'access-control-request-headers'
		);
		if (requestedHeaders) {
			set.headers['Access-Control-Allow-Headers'] = requestedHeaders;
		}

		/*
		 * A preflight is answered without knowing the client: it carries neither credentials nor a body,
		 * so no per-client decision is possible and the client-based restriction applies to the real
		 * request only.
		 *
		 * Returning a bare Response is safe here — set.headers written by this hook and by `nocache`
		 * before it are both merged onto it (measured; see research.md R3).
		 */
		return new Response(null, { status: 204 });
	});
