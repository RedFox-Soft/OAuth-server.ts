import { elysia } from '../../lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { setPeerResolverForTests } from 'lib/helpers/caller_address.ts';

export { resetRateLimiter, setRateLimitClock } from 'lib/plugins/rateLimit.js';

/*
 * `elysia.handle()` has no socket, so the connection's address travels in a header that only this
 * resolver reads. The server under test never sees it as anything but a header it ignores.
 */
export const PEER_HEADER = 'x-test-peer';

export function statePeerThroughHeader(): void {
	setPeerResolverForTests(
		(request) => request.headers.get(PEER_HEADER) ?? undefined
	);
}

export interface Arrival {
	/* The address the connection comes from: a proxy's, or the caller's own when directly exposed. */
	readonly peer: string;
	readonly headers?: Record<string, string>;
	readonly method?: string;
	readonly body?: string;
}

export function send(path: string, arrival: Arrival): Promise<Response> {
	statePeerThroughHeader();
	return elysia.handle(
		new Request(`${ISSUER}${path}`, {
			method: arrival.method ?? 'GET',
			headers: { ...(arrival.headers ?? {}), [PEER_HEADER]: arrival.peer },
			body: arrival.body
		})
	);
}

/* Statuses of `count` sequential arrivals, each built by `arrivalFor(i)`. */
export async function flood(
	path: string,
	count: number,
	arrivalFor: (i: number) => Arrival
): Promise<number[]> {
	const statuses: number[] = [];
	for (let i = 0; i < count; i += 1) {
		statuses.push((await send(path, arrivalFor(i))).status);
	}
	return statuses;
}

export function refusals(statuses: number[]): number {
	return statuses.filter((status) => status === 429).length;
}
