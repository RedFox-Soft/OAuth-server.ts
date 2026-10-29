import { describe, it, beforeAll, beforeEach, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { flood, refusals, resetRateLimiter, send } from './helper.js';

const STRICT_PATH = '/token';

beforeAll(async () => {
	await bootstrap(import.meta.url);
});

/**
 * @proves Behind an ordinary reverse proxy on a private network, with no setting changed, each
 * visitor keeps an allowance of their own.
 */
describe('visitors behind a private-network proxy', () => {
	beforeEach(() => {
		resetRateLimiter();
		ApplicationConfig['clientAddress.source'] = 'automatic';
	});

	it('get two allowances when they come from two addresses', async () => {
		await flood(STRICT_PATH, 4, () => ({
			method: 'POST',
			peer: '172.18.0.3',
			headers: { 'x-forwarded-for': '203.0.113.7' }
		}));

		const other = await send(STRICT_PATH, {
			method: 'POST',
			peer: '172.18.0.3',
			headers: { 'x-forwarded-for': '198.51.100.4' }
		});

		expect(other.status).not.toBe(429);
	});

	it('are each named by the nearest public address through a chain of private proxies', async () => {
		const first = await flood(STRICT_PATH, 4, () => ({
			method: 'POST',
			peer: '10.0.0.2',
			headers: { 'x-forwarded-for': '203.0.113.7, 192.168.1.10, 10.0.5.4' }
		}));
		const second = await flood(STRICT_PATH, 3, () => ({
			method: 'POST',
			peer: '10.0.0.2',
			headers: { 'x-forwarded-for': '198.51.100.4, 192.168.1.10, 10.0.5.4' }
		}));

		expect([refusals(first), refusals(second)]).toEqual([1, 0]);
	});
});
