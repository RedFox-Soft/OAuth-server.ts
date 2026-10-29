import { elysia } from '../../lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { setPeerResolverForTests } from 'lib/helpers/caller_address.ts';

export { resetRateLimiter, setRateLimitClock } from 'lib/plugins/rateLimit.js';

/*
 * Two addresses from the documentation ranges (RFC 5737), so no case can accidentally name something
 * routable. Which one a request carries is the whole subject of the isolation assertions, so they are
 * named rather than inlined.
 */
export const ORIGIN_A = '203.0.113.7';
export const ORIGIN_B = '198.51.100.4';

export interface ProbeInit {
	readonly method?: string;
	readonly headers?: Record<string, string>;
	readonly body?: string;
}

/*
 * One request from a stated origin.
 *
 * The suite runs as the shipped deployment does: `clientAddress.source` is "fly", every connection comes
 * from Fly's proxy on a private address, and the origin travels as the `Fly-Client-IP` that proxy sets.
 * Passing `origin` as null sends a request the proxy named no caller for.
 */
const FLY_PROXY = '172.16.27.146';
export function send(
	path: string,
	origin: string | null,
	init: ProbeInit = {}
): Promise<Response> {
	setPeerResolverForTests(() => FLY_PROXY);
	const headers: Record<string, string> = { ...(init.headers ?? {}) };
	if (origin !== null) {
		headers['Fly-Client-IP'] = origin;
	}

	return elysia.handle(
		new Request(`${ISSUER}${path}`, {
			method: init.method ?? 'GET',
			headers,
			body: init.body
		})
	);
}

/*
 * `count` sequential requests from one origin, returning just the statuses.
 *
 * Sequential rather than concurrent: the counter is read-modify-write with no lock, and a spec that
 * fired in parallel would be asserting against whatever interleaving the runtime happened to pick.
 * Enforcement is a property of the count, not of the concurrency, so the specs drive it in order.
 */
export async function flood(
	path: string,
	origin: string | null,
	count: number,
	init: ProbeInit = {}
): Promise<number[]> {
	const statuses: number[] = [];
	for (let i = 0; i < count; i += 1) {
		statuses.push((await send(path, origin, init)).status);
	}
	return statuses;
}

/* How many of a flood's statuses were rate-limit refusals. */
export function refusals(statuses: number[]): number {
	return statuses.filter((status) => status === 429).length;
}
