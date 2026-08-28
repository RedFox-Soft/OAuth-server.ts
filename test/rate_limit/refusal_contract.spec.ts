import { describe, it, beforeEach, afterEach, expect, mock } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { eventBus } from 'lib/event_bus.js';
import { ORIGIN_A, flood, resetRateLimiter, send } from './helper.js';

const STRICT = () => ApplicationConfig['rateLimit.strict.max'] as number;
const ORDINARY = () => ApplicationConfig['rateLimit.ordinary.max'] as number;

/* Spends an allowance and returns the first refusal, so each case starts from a 429. */
async function refusalOn(
	path: string,
	allowance: number,
	init: { method?: string; headers?: Record<string, string> } = {}
): Promise<Response> {
	await flood(path, ORIGIN_A, allowance, init);
	return send(path, ORIGIN_A, init);
}

describe('rate limit refusal contract', () => {
	describe('what every refusal carries', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		it('answers 429', async () => {
			const refused = await refusalOn('/token', STRICT(), { method: 'POST' });

			expect(refused.status).toBe(429);
		});

		it('states how long to wait, as a positive integer', async () => {
			const refused = await refusalOn('/token', STRICT(), { method: 'POST' });
			const retryAfter = Number(refused.headers.get('retry-after'));

			expect(Number.isInteger(retryAfter)).toBe(true);
			expect(retryAfter).toBeGreaterThanOrEqual(1);
			expect(retryAfter).toBeLessThanOrEqual(
				ApplicationConfig['rateLimit.strict.windowSeconds'] as number
			);
		});

		/*
		 * The limiter is mounted after nocache and securityHeaders precisely so this holds. A refusal
		 * missing headers every other response carries would be a one-header fingerprint.
		 */
		it('carries the same no-store and hardening headers as every other response', async () => {
			const refused = await refusalOn('/token', STRICT(), { method: 'POST' });

			expect(refused.headers.get('cache-control')).toBe('no-store');
			expect(refused.headers.get('surrogate-control')).toBe('no-store');
			expect(refused.headers.get('x-content-type-options')).toBe('nosniff');
			expect(refused.headers.get('referrer-policy')).toBe('no-referrer');
		});

		/*
		 * The draft RateLimit-* header set would disclose the allowance, the remaining count and the
		 * window to every caller — including one probing for the threshold. Retry-After is the one number
		 * a client legitimately needs (FR-007).
		 */
		it('discloses nothing beyond the retry delay', async () => {
			const refused = await refusalOn('/token', STRICT(), { method: 'POST' });

			for (const [name] of refused.headers) {
				expect(name.toLowerCase().startsWith('ratelimit')).toBe(false);
				expect(name.toLowerCase().startsWith('x-ratelimit')).toBe(false);
			}

			const body = await refused.text();
			expect(body).not.toContain(String(STRICT()));
			expect(body.toLowerCase()).not.toContain('allowance');
			expect(body).not.toContain(ORIGIN_A);
		});
	});

	describe('the OAuth channel', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		it('answers in the standard machine-readable error shape', async () => {
			const refused = await refusalOn('/token', STRICT(), { method: 'POST' });
			const body = await refused.json();

			expect(body.error).toBe('temporarily_unavailable');
			expect(typeof body.error_description).toBe('string');
		});

		// A 429 is not a fault, and the error store captures at status >= 500 — so no diagnostic handle
		// is attached, and none should be.
		it('attaches no error reference', async () => {
			const refused = await refusalOn('/token', STRICT(), { method: 'POST' });
			const body = await refused.json();

			expect(body.error_reference).toBeUndefined();
		});

		/*
		 * The MCP surface deliberately receives this same shape rather than a JSON-RPC error. Its own
		 * onError handles validation failures only, and teaching a pre-routing hook the MCP transport
		 * would put a second copy of that contract in the request path. A well-formed 429 carrying
		 * Retry-After is usable by any HTTP client; pinned here so the choice is visible rather than
		 * discovered.
		 */
		it('answers the MCP surface in the same shape, not JSON-RPC', async () => {
			const refused = await refusalOn('/mcp', ORDINARY(), { method: 'POST' });
			const body = await refused.json();

			expect(refused.status).toBe(429);
			expect(body.error).toBe('temporarily_unavailable');
		});
	});

	describe('the admin plane', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		/*
		 * The console reads `message`, not `error_description`. Answering it in the OAuth shape would be
		 * the right status with the wrong body and the reason gone — the same defect the root handler's
		 * admin stand-aside was added to fix.
		 */
		it('answers in the admin shape', async () => {
			const refused = await refusalOn('/admin/api/me', ORDINARY());
			const body = await refused.json();

			expect(refused.status).toBe(429);
			expect(body.error).toBe('admin_error');
			expect(typeof body.message).toBe('string');
		});

		it('still carries the retry delay', async () => {
			const refused = await refusalOn('/admin/api/me', ORDINARY());

			expect(Number(refused.headers.get('retry-after'))).toBeGreaterThanOrEqual(
				1
			);
		});
	});

	describe('a browser-facing page', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		it('answers a person with a page rather than a JSON body', async () => {
			const init = { headers: { accept: 'text/html' } };
			const refused = await refusalOn(
				'/ui/anyinteraction/consent',
				ORDINARY(),
				init
			);

			expect(refused.status).toBe(429);
			expect(refused.headers.get('content-type')).toContain('text/html');
		});

		it('names no account and no client on that page', async () => {
			const init = { headers: { accept: 'text/html' } };
			const refused = await refusalOn(
				'/ui/anyinteraction/consent',
				ORDINARY(),
				init
			);
			const page = await refused.text();

			expect(page).not.toContain('client');
			expect(page).not.toContain(ORIGIN_A);
		});
	});

	/*
	 * Trap 1. OIDCProviderError defaults allow_redirect to true, and the handler turns any redirectable
	 * error raised on /auth into a redirect back to the client. For a refusal that would be wrong twice:
	 * building the redirect means resolving and validating redirect_uri first — the work the refusal
	 * exists to avoid — and it hands an attacker a redirect on an endpoint they have been told to stop
	 * calling. Nothing else in the suite would notice: a 302 to the registered URI looks correct.
	 */
	describe('the authorization endpoint', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		it('refuses in place and does not redirect the caller', async () => {
			const query = new URLSearchParams({
				client_id: 'client',
				response_type: 'code',
				redirect_uri: 'https://client.example.com/cb',
				scope: 'openid',
				state: 'xyz'
			}).toString();

			const refused = await refusalOn(`/auth?${query}`, STRICT());

			expect(refused.status).toBe(429);
			expect(refused.status).not.toBe(302);
			expect(refused.headers.get('location')).toBeNull();
		});
	});

	/*
	 * Trap 2. A 429 is neither 500 nor a gate refusal, so without an explicit exclusion it falls to the
	 * handler's `else` and is announced on `server_error` — deliberate, correct behaviour reported as a
	 * fault, on the one channel an operator cannot afford to learn to ignore.
	 */
	describe('what a refusal reports', () => {
		const listeners: Array<[string, (...args: unknown[]) => void]> = [];

		function listen(channel: string) {
			const spy = mock();
			eventBus.on(channel, spy);
			listeners.push([channel, spy]);
			return spy;
		}

		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		afterEach(() => {
			for (const [channel, spy] of listeners) {
				eventBus.off(channel, spy);
			}
			listeners.length = 0;
		});

		it('is not filed as a server fault', async () => {
			const serverError = listen('server_error');

			await refusalOn('/token', STRICT(), { method: 'POST' });

			expect(serverError).not.toHaveBeenCalled();
		});

		it('announces itself once on its own channel, naming the route and the class', async () => {
			const limited = listen('rate_limited');

			await refusalOn('/token', STRICT(), { method: 'POST' });

			expect(limited).toHaveBeenCalledTimes(1);
			expect(limited.mock.calls[0]?.[0]).toEqual({
				method: 'POST',
				path: '/token',
				class: 'strict',
				origin: ORIGIN_A
			});
		});

		// Four scalar fields and no more: a limited endpoint is still probed with real secrets, and this
		// is the one place they could reach a log (FR-010).
		it('carries no credential material in what it reports', async () => {
			const limited = listen('rate_limited');

			await refusalOn('/token', STRICT(), {
				method: 'POST',
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
					authorization: 'Basic Y2xpZW50OnNlY3JldA=='
				}
			});

			const payload = JSON.stringify(limited.mock.calls[0]?.[0] ?? {});
			expect(payload).not.toContain('secret');
			expect(payload).not.toContain('Basic');
			expect(Object.keys(limited.mock.calls[0]?.[0] as object).sort()).toEqual([
				'class',
				'method',
				'origin',
				'path'
			]);
		});
	});
});
