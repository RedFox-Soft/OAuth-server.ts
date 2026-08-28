import { describe, it, beforeEach, expect } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { ORIGIN_A, flood, refusals, resetRateLimiter, send } from './helper.js';

const STRICT = () => ApplicationConfig['rateLimit.strict.max'] as number;
const PUBLIC = () => ApplicationConfig['rateLimit.public.max'] as number;

/*
 * The ways this feature could take the deployment down by itself (US4).
 *
 * Everything here is a property of the classification table rather than of new code, which is the
 * point: the design puts the exemptions in one declared place, so these specs are what prove that
 * place is right — and what fails if the mount order in lib/index.ts is ever reversed.
 */
describe('rate limit exemptions', () => {
	describe('the liveness probe', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		/*
		 * The platform probes every 30s and takes a machine out of the proxy when the check fails. A
		 * refused health check is the limiter causing the outage it exists to prevent — so the probe is
		 * exempt outright rather than merely generously limited.
		 */
		it('is never refused, however hard it is hit from one origin', async () => {
			const statuses = await flood(
				'/health',
				ORIGIN_A,
				Math.max(PUBLIC(), STRICT()) * 4
			);

			expect(refusals(statuses)).toBe(0);
		});

		it('stays servable even after every other class is exhausted', async () => {
			await flood('/token', ORIGIN_A, STRICT() + 1, { method: 'POST' });
			await flood('/.well-known/openid-configuration', ORIGIN_A, PUBLIC() + 1);

			expect((await send('/health', ORIGIN_A)).status).toBe(200);
		});
	});

	describe('cross-origin preflights', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		/*
		 * A preflight is answered before routing and costs almost nothing. Charged to the class of the
		 * request it precedes, it would halve a browser client's real allowance — refusing it for requests
		 * it never actually sent.
		 */
		it('does not spend the strict allowance of the request they precede', async () => {
			const preflight = {
				method: 'OPTIONS',
				headers: {
					origin: 'https://client.example.com',
					'access-control-request-method': 'POST'
				}
			};

			await flood('/token', ORIGIN_A, STRICT() * 2, preflight);

			// The strict allowance is untouched: a real POST still gets its full run.
			const real = await flood('/token', ORIGIN_A, STRICT(), {
				method: 'POST'
			});
			expect(refusals(real)).toBe(0);
		});
	});

	describe('the administration console', () => {
		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
		});

		/*
		 * The console is one page plus an asset burst from a single address. A limiter that refuses part
		 * of that makes the admin UI unusable, which is why the assets sit in the loose class.
		 */
		it('loads its page and asset burst from one origin unrefused', async () => {
			const page = await send('/admin', ORIGIN_A, {
				headers: { accept: 'text/html' }
			});
			const assets = await flood('/public/admin.js', ORIGIN_A, PUBLIC());

			expect(page.status).not.toBe(429);
			expect(refusals(assets)).toBe(0);
		});

		it('reads a static asset through the prefix, not the wildcard pattern', async () => {
			const nested = await send('/public/assets/nested/app.css', ORIGIN_A);

			expect(nested.status).not.toBe(429);
		});
	});

	/*
	 * FR-013, and the reason the limiter is mounted BEFORE featureGate rather than after.
	 *
	 * Reverse the two and a capability-disabled endpoint answers 404 without ever being counted, while a
	 * path the server does not serve at all is counted and answers 429 under load — making the two
	 * distinguishable by volume alone, which is exactly the fingerprint featureGate exists to eliminate.
	 * This is the spec that fails if that order is ever changed.
	 */
	describe('a disabled capability and an unserved path', () => {
		const DISABLED = '/token/introspect';
		const UNSERVED = '/_not_a_mounted_route';
		const post = {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: 'token=whatever'
		};

		beforeEach(async () => {
			await bootstrap(import.meta.url);
			resetRateLimiter();
			// Off by default in production, and asserted here so the case cannot silently start testing
			// an enabled endpoint.
			ApplicationConfig['introspection.enabled'] = false;
		});

		it('answer identically while both are under the allowance', async () => {
			const disabled = await send(DISABLED, ORIGIN_A, post);
			const unserved = await send(UNSERVED, ORIGIN_A, post);

			expect(disabled.status).toBe(404);
			expect(unserved.status).toBe(404);
			expect(await disabled.text()).toBe(await unserved.text());
		});

		it('answer identically once both are over it', async () => {
			const ordinary = ApplicationConfig['rateLimit.ordinary.max'] as number;

			await flood(DISABLED, ORIGIN_A, ordinary, post);
			const disabled = await send(DISABLED, ORIGIN_A, post);

			resetRateLimiter();
			await flood(UNSERVED, ORIGIN_A, ordinary, post);
			const unserved = await send(UNSERVED, ORIGIN_A, post);

			expect(disabled.status).toBe(429);
			expect(unserved.status).toBe(429);
			expect(await disabled.text()).toBe(await unserved.text());
		});

		// The counted-or-not asymmetry is the actual leak, so it is asserted directly rather than only
		// through the two responses above.
		it('are both counted, so neither can be identified by how long it takes to refuse', async () => {
			const ordinary = ApplicationConfig['rateLimit.ordinary.max'] as number;

			const disabled = await flood(DISABLED, ORIGIN_A, ordinary + 1, post);
			resetRateLimiter();
			const unserved = await flood(UNSERVED, ORIGIN_A, ordinary + 1, post);

			expect(refusals(disabled)).toBe(1);
			expect(refusals(unserved)).toBe(1);
		});
	});
});
