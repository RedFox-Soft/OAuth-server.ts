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
const realFetch = globalThis.fetch;
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
	if (!mockedOrigins.has(url.origin)) {
		return realFetch(input, init);
	}

	const method = (
		init?.method ??
		(typeof input === 'object' && 'method' in input
			? (input as Request).method
			: 'GET')
	).toUpperCase();
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

export function mock(origin: string) {
	if (!isInstalled()) {
		fetchSpy = spyOn(globalThis, 'fetch').mockImplementation(dispatchFetch);
		(globalThis.fetch as MaybeInstalled)[INSTALLED] = true;
	}
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

mock.restore = function restore() {
	fetchSpy?.mockRestore();
	fetchSpy = undefined;
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
