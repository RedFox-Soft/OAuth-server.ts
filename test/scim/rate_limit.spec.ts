import { describe, it, beforeAll, afterEach, expect } from 'bun:test';

import { ApplicationConfig } from 'lib/configs/application.js';
import { elysia } from 'lib/index.js';
import {
	resetScimRateLimiter,
	setScimRateLimitClock
} from 'lib/scim/rate_limit.js';
import bootstrap from '../test_helper.js';
import {
	connect,
	scim,
	scimBucket,
	provider,
	type Connected
} from './helpers.ts';

/**
 * @proves A connection may send the sustained rate IPSIE requires and is refused, in SCIM's own shape and
 * with a Retry-After, only above its own allowance — never because of another tenant, and an unauthenticated
 * caller is held to the strict per-address bound (spec 070, User Story 5, scenarios 5–6; FR-036, FR-037;
 * SC-005).
 */
describe('SCIM rate limiting', () => {
	let a: Connected;
	let b: Connected;
	let now = 1_000_000;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'scim' });
		const bucket = await scimBucket([provider('one'), provider('two')]);
		a = await connect(bucket, { providerId: 'one' });
		b = await connect(bucket, { providerId: 'two' });
	});

	afterEach(() => {
		setScimRateLimitClock(null);
		resetScimRateLimiter();
		ApplicationConfig['scim.rateLimit.max'] = 3000;
		ApplicationConfig['scim.rateLimit.windowSeconds'] = 60;
	});

	it('refuses a connection over its allowance with 429 and Retry-After, leaving another connection unaffected', async () => {
		setScimRateLimitClock(() => now);
		ApplicationConfig['scim.rateLimit.max'] = 30;
		ApplicationConfig['scim.rateLimit.windowSeconds'] = 1;
		for (let i = 0; i < 30; i++) {
			expect(
				(
					await scim('GET', `${a.base}/ServiceProviderConfig`, {
						token: a.token
					})
				).status
			).toBe(200);
		}

		const over = await scim('GET', `${a.base}/ServiceProviderConfig`, {
			token: a.token
		});
		const neighbour = await scim('GET', `${b.base}/ServiceProviderConfig`, {
			token: b.token
		});

		expect(over.status).toBe(429);
		expect(over.headers.get('retry-after')).toBe('1');
		expect(over.json).toMatchObject({
			schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
			status: '429'
		});
		expect(neighbour.status).toBe(200);
	});

	it('never refuses a connection sending 25 requests a second for a minute', async () => {
		setScimRateLimitClock(() => now);
		const statuses = new Set<number>();
		for (let second = 0; second < 60; second++) {
			now += 1;
			for (let i = 0; i < 25; i++) {
				const res = await elysia.handle(
					new Request(`http://e.ly${a.base}/ServiceProviderConfig`, {
						headers: {
							authorization: `Bearer ${a.token}`,
							'x-forwarded-for': '198.51.100.7'
						}
					})
				);
				statuses.add(res.status);
			}
		}

		expect([...statuses]).toEqual([200]);
	});

	it('refuses an unauthenticated caller with 429 once over the strict per-address bound', async () => {
		setScimRateLimitClock(() => now);
		const strict = ApplicationConfig['rateLimit.strict.max'] as number;
		const attempt = () =>
			elysia.handle(
				new Request(`http://e.ly${a.base}/Users`, {
					headers: {
						authorization: 'Bearer guess',
						'x-forwarded-for': '203.0.113.9'
					}
				})
			);
		for (let i = 0; i < strict; i++) {
			expect((await attempt()).status).toBe(401);
		}

		const over = await attempt();

		expect(over.status).toBe(429);
	});
});
