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

const STRICT = () => ApplicationConfig['rateLimit.strict.max'];
const STRICT_PATH = '/token';

const post = { method: 'POST' };

/*
 * Which caller a request is counted against, on the shipped deployment (FR-002). Every other choice of
 * how the server is reached, and every forged header, is test/caller_address/'s subject; this file keeps
 * the two properties the limiter itself depends on.
 */
/**
 * @proves Behind Fly's proxy each caller the proxy names has its own allowance, and requests the
 * proxy names no caller for are still bounded.
 */
describe('rate limit origin resolution', () => {
	beforeEach(async () => {
		await bootstrap(import.meta.url);
		resetRateLimiter();
	});

	it('counts two Fly-Client-IP values as two origins', async () => {
		await flood(STRICT_PATH, ORIGIN_A, STRICT() + 1, post);

		expect((await send(STRICT_PATH, ORIGIN_B, post)).status).not.toBe(429);
	});

	it('ignores an X-Forwarded-For a caller sends alongside the Fly-Client-IP the proxy set', async () => {
		const spoofed = {
			...post,
			headers: { 'Fly-Client-IP': ORIGIN_A, 'x-forwarded-for': ORIGIN_B }
		};

		await flood(STRICT_PATH, null, STRICT() + 1, spoofed);

		// ORIGIN_B was only ever in the header the caller wrote, so its own allowance is untouched.
		expect((await send(STRICT_PATH, ORIGIN_B, post)).status).not.toBe(429);
	});

	/*
	 * Requests the proxy named no caller for are counted against the proxy's own address, together. Noisy
	 * and visible, which is the point: letting them through unlimited would make a missing header the way
	 * around the limiter.
	 */
	it('throttles requests carrying no origin together', async () => {
		const statuses = await flood(STRICT_PATH, null, STRICT() + 1, post);

		expect(refusals(statuses)).toBe(1);
	});
});
