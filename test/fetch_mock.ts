import { spyOn } from 'bun:test';

// Bun-native replacement for undici's MockAgent, used to intercept the provider's OUTBOUND
// `fetch` calls (backchannel logout, sector_identifier_uri, jwks_uri). Bun's global fetch is not
// dispatched through undici, so `setGlobalDispatcher(new MockAgent())` has no effect here; instead
// we `spyOn(globalThis, 'fetch')` with a matcher while preserving the undici surface the specs use:
//   mock(origin).intercept({ path, method?, body? }).reply(status, body?, { headers? })
//   assertNoPendingInterceptors()  — throws if a registered interceptor was never hit
//   mock.restore()                 — restore fetch and drop all interceptors
// Requests to an origin that was never passed to mock() fall through to the real fetch untouched
// (e.g. Eden `treaty` calls the app directly and never reaches here); requests to a mocked origin
// with no matching interceptor throw, matching MockAgent's no-net-connect behaviour.
type MockInterceptor = {
	origin: string;
	path: string;
	method: string;
	bodyMatcher?: (value: string) => boolean;
	status: number;
	body?: string | null;
	headers?: Record<string, string>;
	consumed: boolean;
};

const mockInterceptors: MockInterceptor[] = [];
const mockedOrigins = new Set<string>();
/* No handle on the real `fetch` is kept, deliberately: nothing here may fall back to it. */
let fetchSpy: ReturnType<typeof spyOn> | undefined;

/*
 * Marks the `fetch` this module installed. Everything above is module state, which outlives a spec
 * file — but the patch on `globalThis.fetch` does not, because Bun restores it at the file boundary.
 * A spec that registers an interceptor and ends without `mock.restore()` therefore leaves `fetchSpy`
 * set while nothing is intercepting, and a `??=` guard on that handle would skip reinstalling and
 * let the next file's requests reach the real network. Ask the live global what it is instead.
 */
const INSTALLED = Symbol.for('test.fetchMock.installed');
type MaybeInstalled = typeof globalThis.fetch & { [INSTALLED]?: true };

function isInstalled(): boolean {
	return (globalThis.fetch as MaybeInstalled)[INSTALLED] === true;
}

async function dispatchFetch(
	input: RequestInfo | URL,
	init?: RequestInit
): Promise<Response> {
	const href =
		typeof input === 'string'
			? input
			: input instanceof URL
				? input.href
				: (input as Request).url;
	const url = new URL(href);
	const method = (
		init?.method ??
		(typeof input === 'object' && 'method' in input
			? (input as Request).method
			: 'GET')
	).toUpperCase();

	if (!mockedOrigins.has(url.origin)) {
		/*
		 * A refusal, not a fall-through to the real network. Falling through was the original design
		 * and it is how a test reaches DNS: `mock.restore()` and `assertNoPendingInterceptors()` both
		 * clear the registered set process-wide, so a case that issues a request without registering
		 * its origin — because its author expected a refusal, or because a sibling case cleaned up
		 * first — got a real lookup. A federation case resolving a `.test` hostname once burned 52
		 * minutes that way and dragged a whole run to 3,226 s, and the shape of the failure said
		 * nothing about what had actually gone wrong.
		 */
		throw new Error(
			`test fetch to an unregistered origin: ${method} ${url.href}. ` +
				`Register it with mock('${url.origin}') and intercept the path, or the request would ` +
				'reach the real network.'
		);
	}

	const path = url.pathname + url.search;

	const interceptor = mockInterceptors.find(
		(i) =>
			!i.consumed &&
			i.origin === url.origin &&
			i.path === path &&
			i.method === method
	);
	if (!interceptor) {
		throw new Error(`No mock interceptor for ${method} ${url.href}`);
	}

	if (interceptor.bodyMatcher) {
		const raw = init?.body;
		const bodyText =
			raw == null
				? ''
				: raw instanceof URLSearchParams
					? raw.toString()
					: typeof raw === 'string'
						? raw
						: String(raw);
		if (interceptor.bodyMatcher(bodyText) === false) {
			throw new Error(`mock body matcher rejected ${method} ${url.href}`);
		}
	}

	interceptor.consumed = true;
	return new Response(interceptor.body ?? null, {
		status: interceptor.status,
		headers: interceptor.headers
	});
}

/*
 * Idempotent, and called from `test/preload.ts` before every test rather than lazily on the first
 * `mock()` call. Lazily was not enough: interception only existed in files that asked for it, so
 * whether a stray request reached the network depended on which files the runner had walked — and the
 * walk order differs between Windows and CI, and shifts whenever a spec file is added or removed.
 * Installed unconditionally, no spec has to remember and the order stops mattering.
 */
export function installFetchInterception(): void {
	if (isInstalled()) {
		/*
		 * The spy now outlives a single test, so its call log has to be emptied or a spec that counts
		 * requests counts every earlier test's as well. `client_keystore.spec.ts` asserts exactly one
		 * concurrent fetch and saw 26 the first time this ran suite-wide.
		 */
		fetchSpy?.mockClear();
		return;
	}
	fetchSpy = spyOn(globalThis, 'fetch').mockImplementation(dispatchFetch);
	(globalThis.fetch as MaybeInstalled)[INSTALLED] = true;
}

export function mock(origin: string) {
	if (!isInstalled()) installFetchInterception();
	mockedOrigins.add(origin);
	return {
		intercept(opts: {
			path: string;
			method?: string;
			body?: (value: string) => boolean;
		}) {
			const interceptor: MockInterceptor = {
				origin,
				path: opts.path,
				method: (opts.method ?? 'GET').toUpperCase(),
				bodyMatcher: opts.body,
				status: 200,
				consumed: false
			};
			return {
				reply(
					status: number,
					body?: string,
					init?: { headers?: Record<string, string> }
				) {
					interceptor.status = status;
					interceptor.body = body ?? null;
					interceptor.headers = init?.headers;
					mockInterceptors.push(interceptor);
					return interceptor;
				}
			};
		}
	};
}

/*
 * Drops the registrations, keeps the interception. Uninstalling the spy here is what made a
 * mid-file `assertNoPendingInterceptors()` reopen the network for whatever ran next; leaving it in
 * place means a request after cleanup is refused by name instead. `test/preload.ts` reinstalls before
 * every test anyway, since Bun restores `globalThis.fetch` at each file boundary.
 */
mock.restore = function restore() {
	mockInterceptors.length = 0;
	mockedOrigins.clear();
};

export function assertNoPendingInterceptors() {
	const pending = mockInterceptors.filter((i) => !i.consumed);
	const details = pending.map((i) => `${i.method} ${i.origin}${i.path}`);
	mock.restore();
	if (pending.length) {
		throw new Error(`pending mock interceptors: ${details.join(', ')}`);
	}
}
