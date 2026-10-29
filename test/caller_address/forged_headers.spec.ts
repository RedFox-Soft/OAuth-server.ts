import { describe, it, beforeAll, beforeEach, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { flood, refusals, resetRateLimiter } from './helper.js';

/*
 * One caller, one allowance of three on a strict route: the fourth request from it is refused. Every
 * case rotates what a caller can write — forwarded headers — and asks whether that bought a fresh
 * allowance. A refusal on the fourth request means it did not.
 */
const STRICT_PATH = '/token';
const FOUR = 4;

const CALLER = '203.0.113.7';
const PRIVATE_PROXY = '10.0.0.2';

beforeAll(async () => {
	await bootstrap(import.meta.url);
});

/**
 * @proves A caller that can only write request headers cannot choose the address the server
 * attributes it to, under every choice of how the server is reached.
 */
describe('a forged forwarded header', () => {
	beforeEach(() => {
		resetRateLimiter();
		ApplicationConfig['clientAddress.source'] = 'automatic';
		ApplicationConfig['clientAddress.trustedProxies'] = [];
	});

	it('does not buy a directly exposed caller a fresh allowance', async () => {
		const statuses = await flood(STRICT_PATH, FOUR, (i) => ({
			method: 'POST',
			peer: CALLER,
			headers: {
				'x-forwarded-for': `192.0.2.${i}`,
				'x-real-ip': `192.0.2.${i + 50}`,
				'fly-client-ip': `192.0.2.${i + 100}`
			}
		}));

		expect(refusals(statuses)).toBe(1);
	});

	it('is ignored behind a private proxy, which attributes the request to the address it appended', async () => {
		const statuses = await flood(STRICT_PATH, FOUR, (i) => ({
			method: 'POST',
			peer: PRIVATE_PROXY,
			headers: { 'x-forwarded-for': `192.0.2.${i}, ${CALLER}` }
		}));

		expect(refusals(statuses)).toBe(1);
	});

	it('is ignored under fly when the connection is not from a private network', async () => {
		ApplicationConfig['clientAddress.source'] = 'fly';

		const statuses = await flood(STRICT_PATH, FOUR, (i) => ({
			method: 'POST',
			peer: CALLER,
			headers: { 'fly-client-ip': `192.0.2.${i}` }
		}));

		expect(refusals(statuses)).toBe(1);
	});

	it('to the left of the entry Cloudflare appended is ignored under cloudflare', async () => {
		ApplicationConfig['clientAddress.source'] = 'cloudflare';

		const statuses = await flood(STRICT_PATH, FOUR, (i) => ({
			method: 'POST',
			peer: PRIVATE_PROXY,
			headers: {
				'x-forwarded-for': `192.0.2.${i}, ${CALLER}, 173.245.48.1`
			}
		}));

		expect(refusals(statuses)).toBe(1);
	});

	it('names a separate caller under listed when its address is not in the operator’s ranges', async () => {
		ApplicationConfig['clientAddress.source'] = 'listed';
		ApplicationConfig['clientAddress.trustedProxies'] = ['198.51.100.0/24'];

		const statuses = await flood(STRICT_PATH, FOUR, (i) => ({
			method: 'POST',
			peer: '198.51.100.9',
			headers: { 'x-forwarded-for': `${CALLER}, 192.0.2.${i}` }
		}));

		expect(refusals(statuses)).toBe(0);
	});

	it('from a client in shared address space is ignored, because that client is the caller', async () => {
		const statuses = await flood(STRICT_PATH, FOUR, (i) => ({
			method: 'POST',
			peer: '100.64.1.2',
			headers: { 'x-forwarded-for': `192.0.2.${i}` }
		}));

		expect(refusals(statuses)).toBe(1);
	});

	it('that is not an address never becomes the caller', async () => {
		const statuses = await flood(STRICT_PATH, FOUR, (i) => ({
			method: 'POST',
			peer: PRIVATE_PROXY,
			headers: { 'x-forwarded-for': `not-an-address-${i}` }
		}));

		expect(refusals(statuses)).toBe(1);
	});
});
