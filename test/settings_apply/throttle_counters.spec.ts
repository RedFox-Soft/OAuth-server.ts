import { describe, it, expect, beforeEach } from 'bun:test';

import bootstrap from '../test_helper.js';
import { configStore } from 'lib/adapters/index.js';
import { ORIGIN_A, flood, send } from '../rate_limit/helper.js';
import { saveSettings, superAdminCookie } from './helpers.js';

const PUBLIC_PATH = '/.well-known/openid-configuration';

/**
 * @proves Applying a setting never hands an origin already being refused a fresh allowance.
 */
describe('the per-origin limiter while its settings are changed', () => {
	let cookie: string;

	beforeEach(async () => {
		await bootstrap(import.meta.url);
		await configStore.set({});
		cookie = await superAdminCookie();
		await saveSettings(cookie, {
			'rateLimit.enabled': true,
			'rateLimit.trustedProxy': true,
			'rateLimit.maxTrackedOrigins': 100,
			'rateLimit.public.max': 2,
			'rateLimit.public.windowSeconds': 60
		});
	});

	/*
	 * The capacity is the one setting whose value is held by a structure rather than read from the
	 * settings, so applying it means changing that structure — and the counters inside it are what
	 * stands between an origin and an unlimited allowance. Rebuilding the structure would make editing
	 * an unrelated-looking number a way to forgive an attacker mid-flood.
	 */
	it('keeps refusing an origin at its limit after the tracking capacity changes', async () => {
		const statuses = await flood(PUBLIC_PATH, ORIGIN_A, 3);
		expect(statuses).toEqual([200, 200, 429]);

		const saved = await saveSettings(cookie, {
			'rateLimit.maxTrackedOrigins': 50
		});
		expect(saved.status).toBe(200);

		expect((await send(PUBLIC_PATH, ORIGIN_A)).status).toBe(429);
	});

	it('refuses an origin at the allowance in force rather than the one it started under', async () => {
		expect(await flood(PUBLIC_PATH, ORIGIN_A, 2)).toEqual([200, 200]);

		await saveSettings(cookie, { 'rateLimit.public.max': 4 });

		expect((await send(PUBLIC_PATH, ORIGIN_A)).status).toBe(200);
	});
});
