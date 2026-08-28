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

/*
 * The allowances the sibling rate_limit.config.ts sets. Read from the live settings rather than
 * restated, so a change there cannot leave these specs asserting against a number nothing uses.
 */
const STRICT = () => ApplicationConfig['rateLimit.strict.max'] as number;
const PUBLIC = () => ApplicationConfig['rateLimit.public.max'] as number;

/* A strict-class route that needs no client, no body and no session to reach the limiter. */
const STRICT_PATH = '/token';
/* A public-class route, for proving the classes do not share a counter. */
const PUBLIC_PATH = '/.well-known/openid-configuration';

describe('rate limit enforcement', () => {
	describe('one origin against its allowance', () => {
		// Inside the describe, not at the top level: a top-level beforeEach does not reset
		// describe-nested tests in this runner, and every case here depends on a clean counter.
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		it('serves every request up to the allowance on its own merits', async () => {
			const statuses = await flood(STRICT_PATH, ORIGIN_A, STRICT(), {
				method: 'POST'
			});

			expect(refusals(statuses)).toBe(0);
		});

		it('refuses the request after the allowance is spent', async () => {
			await flood(STRICT_PATH, ORIGIN_A, STRICT(), { method: 'POST' });

			const over = await send(STRICT_PATH, ORIGIN_A, { method: 'POST' });

			expect(over.status).toBe(429);
		});

		it('keeps refusing while the window is still open', async () => {
			const statuses = await flood(STRICT_PATH, ORIGIN_A, STRICT() + 5, {
				method: 'POST'
			});

			expect(refusals(statuses)).toBe(5);
		});

		/*
		 * A refused request that counted would let a client which ignores Retry-After extend its own
		 * penalty with every retry — a permanent ban arrived at by accident, with no operator action
		 * behind it. Proven from the outside here, and at the arithmetic level in window_arithmetic.spec.
		 */
		it('does not extend the penalty when a refused origin keeps knocking', async () => {
			await flood(STRICT_PATH, ORIGIN_A, STRICT() + 20, { method: 'POST' });

			// The counter is still exactly at the allowance, so the retry delay has not grown.
			const refused = await send(STRICT_PATH, ORIGIN_A, { method: 'POST' });
			const retryAfter = Number(refused.headers.get('retry-after'));

			expect(refused.status).toBe(429);
			expect(retryAfter).toBeLessThanOrEqual(
				ApplicationConfig['rateLimit.strict.windowSeconds'] as number
			);
		});
	});

	describe('isolation between origins', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		it('serves a second origin normally while the first is being refused', async () => {
			await flood(STRICT_PATH, ORIGIN_A, STRICT() + 1, { method: 'POST' });

			const other = await send(STRICT_PATH, ORIGIN_B, { method: 'POST' });

			expect(other.status).not.toBe(429);
		});

		it('gives each origin its own full allowance', async () => {
			const a = await flood(STRICT_PATH, ORIGIN_A, STRICT(), {
				method: 'POST'
			});
			const b = await flood(STRICT_PATH, ORIGIN_B, STRICT(), {
				method: 'POST'
			});

			expect(refusals(a)).toBe(0);
			expect(refusals(b)).toBe(0);
		});
	});

	describe('isolation between route classes', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		/*
		 * The two classes carry different allowances in the config precisely so this case cannot pass by
		 * coincidence: if they shared a counter, the public request below would already be over.
		 */
		it('leaves the public allowance untouched when the strict one is spent', async () => {
			await flood(STRICT_PATH, ORIGIN_A, STRICT() + 1, { method: 'POST' });

			const publicRes = await send(PUBLIC_PATH, ORIGIN_A);

			expect(publicRes.status).toBe(200);
		});

		it('refuses the public class on its own, larger allowance', async () => {
			const statuses = await flood(PUBLIC_PATH, ORIGIN_A, PUBLIC() + 1);

			expect(refusals(statuses)).toBe(1);
			expect(PUBLIC()).toBeGreaterThan(STRICT());
		});
	});

	/*
	 * FR-003. The refusal has to precede the work, not merely replace the response — otherwise the
	 * limiter costs the server exactly what it was added to save, and a password guess still burns an
	 * argon2 verify on a shared-CPU machine.
	 */
	describe('the refusal precedes the work', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		it('refuses a sign-in without checking the password, even a correct one', async () => {
			const body = new URLSearchParams({
				login: 'user@example.com',
				password: 'correct-password'
			}).toString();
			const init = {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body
			};

			await flood('/ui/anyinteraction/login', ORIGIN_A, STRICT(), init);
			const refused = await send('/ui/anyinteraction/login', ORIGIN_A, init);

			expect(refused.status).toBe(429);
			// No session cookie: the handler that would have issued one never ran.
			expect(refused.headers.get('set-cookie')).toBeNull();
		});
	});

	describe('when the limiter is switched off', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
			ApplicationConfig['rateLimit.enabled'] = false;
		});

		it('never refuses, however far past the allowance one origin goes', async () => {
			const statuses = await flood(STRICT_PATH, ORIGIN_A, STRICT() * 3, {
				method: 'POST'
			});

			expect(refusals(statuses)).toBe(0);
		});
	});
});
