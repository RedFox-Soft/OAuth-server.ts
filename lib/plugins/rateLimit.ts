import type { Elysia } from 'elysia';
import QuickLRU from 'quick-lru';

import { ApplicationConfig } from 'lib/configs/application.js';
import { eventBus } from 'lib/event_bus.js';
import { RateLimited } from 'lib/helpers/errors.js';
import {
	decide,
	type OriginCounter,
	type RateBounds
} from 'lib/helpers/rate_limit_window.js';
import {
	rateClassForRequest,
	type RateClass
} from 'lib/consts/route_classification.js';

/*
 * Per-origin request rate limiting: one origin that exceeds its allowance inside a window is refused,
 * cheaply, before the endpoint it addressed does any work.
 *
 * WHY onRequest, and WHY here in the chain. onRequest precedes routing, so it reaches every response
 * the server emits — handler returns, raw Responses, error-pipeline output, the named adminApp
 * instance, and static files. It is also the only stage ahead of client authentication and body
 * parsing, which is what makes a refusal cost less than the request it refuses instead of merely
 * replacing its body. The position within the chain is argued at the mount site in lib/index.ts; the
 * short version is that it must follow nocache and securityHeaders so the 429 is not missing headers
 * every other response carries, and must PRECEDE featureGate so a capability-disabled endpoint and an
 * unserved path stay indistinguishable under load.
 *
 * WHY per instance, in memory, never persisted. A counter written to the datastore on every single
 * request would put a round-trip in front of the whole server to save the cost of the requests it
 * refuses — an amplifier, not a defence, on a shared-CPU machine. The price is that the effective
 * allowance multiplies by the number of machines serving concurrently and that a restart clears every
 * counter. Both are documented for operators rather than hidden, and both are why this is described as
 * a resource protection and not a security boundary: the properties that must hold absolutely live in
 * the per-identity throttles (lib/helpers/rate_window.ts and the verification attempt caps), which
 * this feature leaves untouched and does not duplicate.
 *
 * Callback-shaped (the lib/plugins/noCache.ts form) rather than a named Elysia instance, for the
 * reason lib/plugins/cors.ts:36 gives: the hook is inlined into the caller's instance, so there is no
 * `as: 'scoped'` reasoning and no way for it to leak onto a sibling route.
 */

/*
 * One bounded store per class, so exhausting one class cannot evict another's counters.
 *
 * WHY an LRU and not a Map. The key is supplied by the caller. An unbounded map keyed on it is itself
 * the memory-exhaustion vector this feature was added to prevent — strictly worse than having no
 * limiter, because an attacker rotating source addresses would consume memory instead of merely CPU.
 * The bound makes the cost a constant the operator sets.
 *
 * No TTL, matching the client-validation memo: an expired window is detected on read and reset in
 * place, so a stale entry costs nothing until it is looked at. A sweep timer would keep the process
 * alive and need tearing down in every spec file for no property the bound does not already give.
 *
 * ACCEPTED CONSEQUENCE. Under an address-rotation flood the LRU evicts, so an honest origin can lose
 * its counter and receive a fresh allowance. That fails open under an attack this limiter cannot stop
 * anyway, and never fails closed against honest traffic — the correct direction for the trade.
 */
const stores = new Map<RateClass, QuickLRU<string, OriginCounter>>();

/*
 * Read at call time rather than captured at module scope: `rateLimit.maxTrackedOrigins` is a setting,
 * and a store sized at import would ignore whatever a spec or a restart put there.
 */
function storeFor(rateClass: RateClass): QuickLRU<string, OriginCounter> {
	const existing = stores.get(rateClass);
	if (existing) {
		return existing;
	}
	const created = new QuickLRU<string, OriginCounter>({
		maxSize: ApplicationConfig['rateLimit.maxTrackedOrigins'] as number
	});
	stores.set(rateClass, created);
	return created;
}

/*
 * The clock, injectable for the tests only.
 *
 * Window expiry is the one property the integration specs cannot prove without waiting, and a suite
 * that sleeps for a window is a suite nobody runs. Exists for the same stated reason
 * reloadConfiguration does — the deployment never touches it.
 */
let clock: () => number = () => Math.floor(Date.now() / 1000);

export function setRateLimitClock(next: (() => number) | null): void {
	clock = next ?? (() => Math.floor(Date.now() / 1000));
}

/* Drops every counter. Called from `beforeEach`, so one spec's flood cannot decide the next one. */
export function resetRateLimiter(): void {
	stores.clear();
}

function boundsFor(rateClass: RateClass): RateBounds {
	/*
	 * `exempt` never reaches this, and `ordinary` is the fallback for every unclassified route — so the
	 * three keyed classes are exhaustive for anything that gets counted.
	 */
	const key =
		rateClass === 'strict' || rateClass === 'public' ? rateClass : 'ordinary';
	return {
		max: ApplicationConfig[`rateLimit.${key}.max`] as number,
		windowSeconds: ApplicationConfig[`rateLimit.${key}.windowSeconds`] as number
	};
}

/*
 * Everything unattributable shares one bucket, deliberately. Letting it through unlimited would make
 * omitting a header the way to bypass the limiter; throttling it together is noisy and visible, which
 * is what a misconfigured origin resolver should be.
 */
const UNATTRIBUTED = 'unknown';

/*
 * Who this request is counted against.
 *
 * The transport peer address is the proxy for every request on the shipped deployment, so counting on
 * it would put the entire internet into one bucket and refuse everyone within seconds of launch. The
 * forwarded headers are therefore read first — but they are client-supplied, so whether they are
 * believed is a deployment declaration (`rateLimit.trustedProxy`) rather than a constant. Trusting
 * them while directly exposed lets any caller rotate the header per request; not trusting them while
 * behind the proxy collapses everyone together. There is no value that is safe in both.
 *
 * Truncated because the header is attacker-controlled in length, and an untruncated key is a memory
 * amplifier even behind the LRU bound. Same 64 characters lib/error_store/redact.ts:82 settled on.
 */
function originOf(request: Request, server: unknown): string {
	if (ApplicationConfig['rateLimit.trustedProxy'] === true) {
		const forwarded =
			request.headers.get('fly-client-ip')?.trim() ||
			request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
			request.headers.get('x-real-ip')?.trim();
		return forwarded ? forwarded.slice(0, 64) : UNATTRIBUTED;
	}

	/*
	 * Elysia hands the server instance to the hook only when one is listening; the specs drive
	 * `elysia.handle()` directly, where there is none. A missing peer is the unattributed bucket rather
	 * than an error — an origin the server genuinely cannot name is still traffic it must bound.
	 */
	const address = (
		server as { requestIP?: (r: Request) => { address?: string } | null } | null
	)?.requestIP?.(request)?.address;
	return address ? address.slice(0, 64) : UNATTRIBUTED;
}

export const rateLimit = (app: Elysia) =>
	app.onRequest(({ request, server }) => {
		if (ApplicationConfig['rateLimit.enabled'] !== true) {
			return;
		}

		const url = request.url;
		/*
		 * Same trick featureGate uses, and for the same reason: `Request.url` is always absolute, so the
		 * path starts at the first '/' after the scheme separator, and constructing a URL object on every
		 * request to the server buys nothing.
		 */
		const start = url.indexOf('/', url.indexOf('://') + 3);
		const query = start === -1 ? -1 : url.indexOf('?', start);
		const path =
			start === -1
				? '/'
				: query === -1
					? url.slice(start)
					: url.slice(start, query);

		const rateClass = rateClassForRequest(request.method, path);
		if (rateClass === 'exempt') {
			return;
		}

		const origin = originOf(request, server);
		const store = storeFor(rateClass);
		const now = clock();
		const decision = decide(store.get(origin), now, boundsFor(rateClass));

		store.set(origin, decision.next);

		if (!decision.refused) {
			return;
		}

		/*
		 * The operator's only way to see the limiter working, since the response deliberately says
		 * nothing beyond the fact of the limit. Four scalar fields and no more: a limited endpoint is
		 * still probed with real secrets, and this is the one place they could reach a log — the same
		 * reasoning the feature_disabled emit carries at lib/plugins/featureGate.ts:66.
		 */
		eventBus.emit('rate_limited', {
			method: request.method,
			path,
			class: rateClass,
			origin
		});

		/*
		 * The console answers in its own shape, and the root handler stands aside for it on a marker
		 * carried by the error. Scoped to `/admin` rather than to the whole admin plane: `/mcp` has an
		 * onError of its own that handles validation failures only, so marking a refusal there would hand
		 * it to a handler that answers for nothing — it receives the OAuth JSON body instead, which is
		 * well-formed, carries Retry-After, and is pinned by test so the choice stays visible.
		 */
		const isConsole = path === '/admin' || path.startsWith('/admin/');

		throw new RateLimited(decision.retryAfterSeconds, rateClass, isConsole);
	});
