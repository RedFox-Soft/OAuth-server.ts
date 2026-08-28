import { describe, it, beforeEach, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ApplicationConfig } from 'lib/configs/application.ts';
import {
	ORIGIN_A,
	ORIGIN_B,
	flood,
	refusals,
	resetRateLimiter,
	send
} from './helper.js';

const STRICT = () => ApplicationConfig['rateLimit.strict.max'] as number;
const STRICT_PATH = '/token';

const post = { method: 'POST' };

/* Drives a flood carrying arbitrary headers instead of the helper's Fly-Client-IP. */
function withHeaders(headers: Record<string, string>) {
	return { ...post, headers };
}

/*
 * Which caller a request is attributed to (FR-002).
 *
 * Everything else in this feature is downstream of getting this right: attribute two callers to one
 * bucket and honest traffic is refused together; attribute one caller to two and the limit does not
 * exist. Both failures look like a working server.
 */
describe('rate limit origin resolution', () => {
	describe('behind a trusted proxy', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
			ApplicationConfig['rateLimit.trustedProxy'] = true;
		});

		it('counts two Fly-Client-IP values as two origins', async () => {
			await flood(STRICT_PATH, ORIGIN_A, STRICT() + 1, post);

			expect((await send(STRICT_PATH, ORIGIN_B, post)).status).not.toBe(429);
		});

		it('reads the first hop of a multi-hop X-Forwarded-For', async () => {
			const first = withHeaders({
				'x-forwarded-for': `${ORIGIN_A}, 70.41.3.18, 150.172.238.178`
			});
			// Same first hop, different downstream hops: still one origin.
			const same = withHeaders({
				'x-forwarded-for': `${ORIGIN_A}, 10.0.0.1`
			});

			const statuses = await flood(STRICT_PATH, null, STRICT(), first);
			expect(refusals(statuses)).toBe(0);

			expect((await send(STRICT_PATH, null, same)).status).toBe(429);
		});

		it('distinguishes two different first hops', async () => {
			await flood(
				STRICT_PATH,
				null,
				STRICT() + 1,
				withHeaders({ 'x-forwarded-for': `${ORIGIN_A}, 10.0.0.1` })
			);

			const other = await send(
				STRICT_PATH,
				null,
				withHeaders({ 'x-forwarded-for': `${ORIGIN_B}, 10.0.0.1` })
			);

			expect(other.status).not.toBe(429);
		});

		// Fly-Client-IP is what the deployment's own proxy sets, so it wins over a header the client
		// upstream of that proxy may have supplied itself.
		it('prefers Fly-Client-IP over X-Forwarded-For', async () => {
			const spoofed = {
				...post,
				headers: { 'Fly-Client-IP': ORIGIN_A, 'x-forwarded-for': ORIGIN_B }
			};

			await flood(STRICT_PATH, null, STRICT() + 1, spoofed);

			// ORIGIN_B was only ever in the untrusted header, so its own allowance is untouched.
			expect((await send(STRICT_PATH, ORIGIN_B, post)).status).not.toBe(429);
		});

		it('falls back to X-Real-IP when neither of the others is present', async () => {
			const realIp = withHeaders({ 'x-real-ip': ORIGIN_A });

			const statuses = await flood(STRICT_PATH, null, STRICT(), realIp);
			expect(refusals(statuses)).toBe(0);

			expect((await send(STRICT_PATH, null, realIp)).status).toBe(429);
		});

		/*
		 * Unattributable traffic shares one bucket and is throttled together. Noisy and visible, which is
		 * the point: the alternative — letting it through unlimited — would make a missing header the way
		 * to bypass the limiter entirely.
		 */
		it('throttles requests carrying no origin at all, in one shared bucket', async () => {
			const statuses = await flood(STRICT_PATH, null, STRICT() + 1, post);

			expect(refusals(statuses)).toBe(1);
		});
	});

	describe('when the proxy is not trusted', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
			ApplicationConfig['rateLimit.trustedProxy'] = false;
		});

		/*
		 * With the headers ignored and no socket peer available in-process, every caller collapses into
		 * one bucket — which is exactly the outage this setting causes when it is wrong for the
		 * deployment, and why the catalog description names both directions.
		 */
		it('ignores the forwarded headers entirely', async () => {
			await flood(STRICT_PATH, ORIGIN_A, STRICT() + 1, post);

			expect((await send(STRICT_PATH, ORIGIN_B, post)).status).toBe(429);
		});
	});
});
