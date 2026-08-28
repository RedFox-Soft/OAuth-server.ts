import { eventBus } from 'lib/event_bus.js';
import { responseModes } from 'lib/response_modes/index.js';
import { OIDCProviderError } from '../helpers/errors.ts';
import { getErrorHtmlResponse } from '../html/error.tsx';
import { routeNames } from 'lib/consts/param_list.js';
import {
	type Context,
	ErrorContext,
	mapValueError,
	ValidationError
} from 'elysia';
import { isAllowRedirectUri } from 'lib/actions/authorization/authorization.js';
import { ISSUER } from 'lib/configs/env.js';
import { dPoPSigningAlgValues } from 'lib/configs/jwaAlgorithms.js';
import { InvalidDpopProof, UseDpopNonce } from 'lib/helpers/validate_dpop.js';
import { DPoPNonces } from 'lib/helpers/dpop_nonces.js';
import { FeatureDisabled } from 'lib/plugins/featureGate.js';
import { RateLimited } from 'lib/helpers/errors.js';
import { captureFault } from 'lib/error_store/capture.js';
import { fieldNamesOf } from 'lib/error_store/redact.js';
import type { ErrorSurface } from 'lib/adapters/types.js';

/*
 * Which plane a fault arose on, from the route it arrived at.
 *
 * Captured rather than inferred later: a reader filtering by surface is asking "is this the protocol or
 * the interaction pages?", and re-deriving that from a stored route string would mean the answer could
 * drift from the route table it was derived from.
 *
 * `/admin` is here even though the handler stands aside for admin-plane errors, and the distinction is
 * worth stating because it is easy to get backwards: the early exit keys on the `adminPlane` *marker*,
 * which only a deliberate AdminError carries. An unexpected fault inside an admin route carries no
 * marker, so it arrives here like any other — and this is the only place it can be filed under the
 * plane it actually came from. The admin group's own handler records the AdminErrors that do exit.
 */
function surfaceFor(route: string): ErrorSurface {
	if (route === routeNames.mcp || route === routeNames.mcp_metadata) {
		return 'mcp';
	}
	if (route.startsWith('/admin')) {
		return 'admin';
	}
	if (
		route.startsWith('/ui') ||
		route.startsWith('/verify-email') ||
		route.startsWith('/reset-password')
	) {
		return 'interaction';
	}
	return 'oauth';
}

function getFirstError(error: ValidationError) {
	const firstError =
		'valueError' in error ? mapValueError(error.valueError) : error;
	return firstError;
}

export default function getWWWAuthenticate(
	authorization: string,
	isDpop: boolean,
	errorObj: { error: string; error_description?: string }
) {
	let scheme = '';
	if (authorization.startsWith('dpop') || isDpop) {
		scheme = 'DPoP';
	} else if (authorization.startsWith('bearer')) {
		scheme = 'Bearer';
	} else {
		return;
	}
	const obj = {
		realm: ISSUER,
		...errorObj,
		...(scheme === 'DPoP'
			? {
					algs: dPoPSigningAlgValues.join(' ')
				}
			: undefined)
	};

	const wwwAuth = Object.entries(obj)
		.map(([key, val]) => `${key}="${val.replace(/"/g, '\\"')}"`)
		.join(', ');

	return `${scheme} ${wwwAuth}`;
}

function getObjFromError(code: string, errorObj: any) {
	if (errorObj instanceof OIDCProviderError) {
		const { error, error_description } = errorObj;
		return { error, ...(error_description ? { error_description } : {}) };
	}
	if (code === 'VALIDATION') {
		const firstError = getFirstError(errorObj);
		if (firstError.schema.error) {
			const schemaError = firstError.schema.error;
			if (typeof schemaError === 'string') {
				return {
					error: 'invalid_request',
					error_description: firstError.schema.error
				};
			}
			return schemaError;
		}
		const error_description =
			mapValueError(firstError).summary || 'Validation error';
		return {
			error: 'invalid_request',
			error_description
		};
	}
	return {
		error: 'server_error',
		error_description: 'An unexpected error occurred'
	};
}

const mapErrorCode = {
	[routeNames.token]: 'grant.error',
	[routeNames.pushed_authorization_request]:
		'pushed_authorization_request.error',
	[routeNames.authorization]: 'authorization.error',
	[routeNames.device_authorization]: 'device_authorization.error',
	[routeNames.backchannel_authentication]: 'backchannel_authentication.error',
	[routeNames.introspect]: 'introspection.error',
	[routeNames.userinfo]: 'userinfo.error',
	[routeNames.end_session]: 'end_session.error',
	[routeNames.end_session_confirm]: 'end_session_confirm.error',
	[routeNames.revocation]: 'revocation.error'
};

/*
 * An error raised by the administrative control plane, recognised by a marker on the error rather than
 * by the request path — the same choice the FeatureDisabled branch below explains.
 *
 * Duck-typed on purpose: importing AdminError would pull the admin graph into the protocol error path,
 * for a check that only needs to know whose error this is.
 */
function isAdminPlaneError(error: unknown): boolean {
	return typeof error === 'object' && error !== null && 'adminPlane' in error;
}

/*
 * The routes that answer as an OAuth *resource server* rather than as the authorization server.
 *
 * RFC 9449 splits the DPoP failure status along exactly that line: the authorization server reports it
 * as a 400 with the error in the body (§8.2), a resource server as a 401 with the error in
 * `WWW-Authenticate` (§7.1) — and only the 401 gets the challenge header written below. Both DPoP
 * errors carry the 400, because that is where the bulk of DPoP traffic lands.
 */
const dpopProtectedResources = new Set<string>([
	routeNames.userinfo,
	routeNames.mcp
]);

/*
 * The status this error answers with, corrected for where it was raised.
 *
 * Both protected resources used to make this correction themselves, by assigning `err.status = 401` in
 * a catch around `dpopValidate` before rethrowing. Deciding it here instead means a resource cannot be
 * added without it, and the error object is no longer mutated on its way through.
 */
function statusFor(error: OIDCProviderError, route: string) {
	const isDpopFailure =
		error instanceof UseDpopNonce || error instanceof InvalidDpopProof;
	if (isDpopFailure && dpopProtectedResources.has(route)) {
		return 401;
	}
	return error.status;
}

export async function errorHandler(obj: ErrorContext) {
	const { set, route, code, request } = obj;
	let { error } = obj;

	/*
	 * The admin plane answers in its own shape (`{ error: 'admin_error', message, … }`) and has its own
	 * onError to do it. This handler is registered on the root app before adminApp is mounted, so without
	 * this exit it answered first and every admin API error reached the caller as an OAuth
	 * `server_error` body — correct status, wrong shape, message gone. Returning nothing hands the error
	 * to the admin group's handler, which is the one that knows what to say.
	 */
	/*
	 * A per-origin rate-limit refusal, handled here and ahead of every exit below — including the admin
	 * stand-aside — because it is raised from an onRequest hook, before Elysia dispatches into any
	 * mounted sub-instance. Standing aside for it would hand it to a handler that never runs: adminApp's
	 * onError is not reached by a throw the root instance made before routing, and the caller receives
	 * Elysia's bare fallback (the error's message as plain text, no headers, no shape). Measured, not
	 * assumed — that is exactly what the console got before this block existed.
	 *
	 * Retry-After is the one number a refused caller legitimately needs, and the only one they get.
	 * There are deliberately no RateLimit-* headers: the draft set would disclose the allowance, the
	 * remaining count and the window to anyone probing for the threshold.
	 */
	if (error instanceof RateLimited) {
		set.status = 429;
		set.headers['Retry-After'] = String(error.retryAfterSeconds);
		/*
		 * The marker the limiter sets for a console path. Read here to choose the body rather than to
		 * trigger the stand-aside below — the console reads `message`, and answering it in the OAuth
		 * shape would be the right status with the wrong body and the reason gone. Every other surface,
		 * `/mcp` included, falls through to the OAuth body and the HTML branch further down.
		 */
		if (isAdminPlaneError(error)) {
			return { error: 'admin_error', message: error.error_description };
		}
	}

	if (isAdminPlaneError(error)) {
		return;
	}

	/*
	 * `/mcp` renders its own refusals, and its `authorization` header schema means one of them arrives
	 * as a validation error rather than as something thrown — so this exit is keyed on the route, where
	 * the admin one above could use a marker on the error.
	 *
	 * It has to be an exit. An unauthenticated MCP client discovers where to get a token from the
	 * `WWW-Authenticate` challenge on that route's 401, and the 422 this handler would otherwise
	 * produce carries neither the header nor the JSON-RPC body an MCP client can read. Returning
	 * nothing hands the error to the MCP app's own onError, which answers with both.
	 *
	 * Ahead of the emit below deliberately: an MCP refusal reports its reason on `mcp.auth.error` and
	 * nowhere else, and `mapErrorCode` has no `/mcp` entry — so emitting here would file every
	 * credential-less call under `server_error`.
	 */
	if (code === 'VALIDATION' && route === routeNames.mcp) {
		return;
	}
	// Elysia's not-found carries its own status but does not assign set.status before onError runs, so
	// the HTML branch below rendered every missing route as a 200 page titled "200". Applies to a
	// feature-gate refusal and a genuinely unrouted request alike, which is what keeps the two
	// indistinguishable.
	if (code === 'NOT_FOUND') {
		set.status = 404;
	}

	// A feature-gate refusal has already announced itself on its own channel. Reporting it again as a
	// server_error would file deliberate, correct behaviour under the channel operators watch for
	// genuine faults. The marker comes from the thrown error rather than the request path, so the
	// gate's decision is not re-derived here.
	if (error instanceof FeatureDisabled || error instanceof RateLimited) {
		/*
		 * Announced already; emit nothing further.
		 *
		 * A rate-limit refusal joins the gate refusal here for the same reason and needs its own test
		 * rather than inheriting the gate's: it carries a 429, so neither the `set.status === 500` branch
		 * nor anything else below would have caught it, and it would have fallen to the `else` and been
		 * filed on `server_error` — deliberate, correct behaviour reported as a fault, on the one channel
		 * an operator cannot afford to learn to ignore. The error store needs no matching exclusion: it
		 * captures at status >= 500, so a 429 is already outside it.
		 */
	} else if (set.status === 500) {
		eventBus.emit('server_error', error);
	} else {
		const key = mapErrorCode[route] ?? 'server_error';
		eventBus.emit(key, error);
	}

	if (route === routeNames.authorization && error.allow_redirect !== false) {
		try {
			return await authorizationErrorHandler(obj);
		} catch (e) {
			if (e instanceof OIDCProviderError) {
				error = e;
				const key = mapErrorCode[route] ?? 'server_error';
				eventBus.emit(key, error);
			} else {
				eventBus.emit('server_error', e);
			}
		}
	}

	const isOIDError = error instanceof OIDCProviderError;
	const status = isOIDError ? statusFor(error, route) : set.status;
	if (isOIDError) {
		set.status = status;
	}
	if (code === 'UNKNOWN' && !isOIDError) {
		console.error('Unknown error', error);
	}

	/*
	 * Recorded here rather than beside the `server_error` emit above, because only now is the status
	 * final: statusFor corrects a DPoP failure's status by where it was raised, and a fault must be
	 * filed under the status the caller actually received.
	 *
	 * The 500 test is what keeps routine rejections out of the store. A FeatureDisabled refusal cannot
	 * reach this branch — it carries its own 404 — so the deliberate-behaviour exclusion the emit above
	 * documents holds here for free rather than needing a second check.
	 */
	/*
	 * Narrowed once, because `set.status` is a number *or* one of Elysia's status names: comparing a name
	 * against 500 yields false rather than an error, so an un-narrowed test would silently record nothing
	 * on exactly the responses this store exists for. Everything in this codebase assigns numbers, so a
	 * non-number means "not a status we can classify" and is left unrecorded rather than guessed at.
	 */
	const numericStatus = typeof status === 'number' ? status : undefined;
	const reference =
		numericStatus !== undefined && numericStatus >= 500
			? captureFault({
					surface: surfaceFor(route),
					route,
					method: request.method,
					status: numericStatus,
					errorCode: 'server_error',
					error,
					headers: request.headers,
					submittedFields: fieldNamesOf(obj.query)
				})
			: undefined;

	const errorObj = getObjFromError(code, error);
	/*
	 * Attached only where a record exists, so every reference a caller can report resolves to one and
	 * none dangles. An additional member on the error body, which RFC 6749 §5.2 does not close — and it
	 * is opaque, so a spec-compliant client that ignores it loses nothing and one that surfaces it gives
	 * its operator something to quote.
	 *
	 * A separate object rather than a mutation, so the WWW-Authenticate challenge below is built from
	 * the unadorned error: a diagnostic handle has no business in an auth challenge header.
	 */
	const body = reference
		? { ...errorObj, error_reference: reference }
		: errorObj;
	if (isOIDError && status === 401) {
		const auth = request.headers.get('authorization')?.toLowerCase() ?? '';
		const isDpop = !!request.headers.get('dpop');
		const authError = getWWWAuthenticate(auth, isDpop, errorObj);
		if (authError) {
			set.headers['WWW-Authenticate'] = authError;
		}
	}
	if (isOIDError && error instanceof UseDpopNonce) {
		// A use_dpop_nonce error is only useful with a nonce attached, and one can always be produced —
		// so there is no longer a branch here that turns a recoverable protocol error into a 500.
		set.headers['DPoP-Nonce'] = DPoPNonces.fabrica().nextNonce();
	}

	const accept = request.headers.get('accept') || '';
	if (accept.includes('text/html')) {
		return getErrorHtmlResponse(
			set.status,
			errorObj.error,
			errorObj.error_description,
			reference
		);
	}
	return body;
}

async function authorizationErrorHandler({
	code,
	error,
	query,
	body,
	request
}: Context) {
	if (error instanceof ValidationError) {
		const firstError = getFirstError(error);
		if (
			firstError.path === '/redirect_uri' ||
			firstError.path === '/client_id'
		) {
			throw error;
		}
	}

	const params = request.method === 'POST' ? body : query;
	const redirectObj = await isAllowRedirectUri(params);

	const state = redirectObj.state;
	const out = {
		...getObjFromError(code, error),
		...(state ? { state } : {}),
		iss: ISSUER
	};
	let mode = params.response_mode;
	if (!responseModes.has(mode)) {
		mode = 'query';
	}
	const handler = responseModes.get(mode);
	return await handler(
		{ oidc: redirectObj.oidc },
		redirectObj.redirect_uri,
		out
	);
}
