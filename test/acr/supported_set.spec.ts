import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent } from '../test_helper.ts';
import { elysia } from 'lib/index.ts';
import { configuration } from 'lib/configs/application.js';
import { ACR_DISTINCTIONS, RESERVED_ACR_VALUE } from 'lib/consts/acr.ts';

/*
 * Every mounted way of finishing a sign-in, and whether completing it records an authentication
 * context on the session. Declared here and checked against the routes the constructed application
 * actually mounts, so the defect this closes is the sign-in path somebody adds later and forgets to
 * give a context — which no example-based case can close, because the defect is the path nobody
 * thought of.
 */
const SIGN_IN_ROUTES: Record<string, 'records a context' | 'records none'> = {
	'POST /ui/:uid/login': 'records a context',
	'POST /ui/:uid/totp': 'records a context',
	'POST /ui/:uid/totp/enroll': 'records a context',
	'GET /ui/:uid/federation/complete': 'records a context',
	// Stages a pending sign-in and hands off; it writes no login result of its own.
	'POST /ui/:uid/registration': 'records none',
	// Neither finishes an authentication: one records consent, the other abandons the request.
	'POST /ui/:uid/consent': 'records none',
	'POST /ui/:uid/abort': 'records none',
	// Renders a form or starts a redirect. Nothing is authenticated until one of the above is posted.
	'GET /ui/:uid/login': 'records none',
	'GET /ui/:uid/totp': 'records none',
	'GET /ui/:uid/totp/enroll': 'records none',
	'GET /ui/:uid/registration': 'records none',
	'GET /ui/:uid/consent': 'records none',
	'GET /ui/:uid/federation/:providerId/start': 'records none'
};

/**
 * @proves Every authentication context the server advertises is one it can actually produce, and
 * every mounted way of signing in is accounted for as recording one or deliberately not.
 */
describe('what the server says it can report', () => {
	let advertised: string[];

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'acr' });
		const { data } = await agent['.well-known']['openid-configuration'].get();
		advertised = (data as { acr_values_supported: string[] })
			.acr_values_supported;
	});

	it('advertises a set that is not empty', () => {
		// Without this, every for-every below would pass vacuously.
		expect(advertised.length).toBeGreaterThan(0);
	});

	it('advertises only contexts some sign-in can produce', () => {
		const producible = new Set(Object.values(configuration.acrMap));

		for (const value of advertised) {
			expect(producible.has(value), value).toBe(true);
		}
	});

	it('advertises every context some sign-in can produce', () => {
		for (const distinction of ACR_DISTINCTIONS) {
			expect(advertised, distinction).toContain(
				configuration.acrMap[distinction]
			);
		}
	});

	it('advertises no context carrying the reserved level-zero meaning', () => {
		expect(advertised).not.toContain(RESERVED_ACR_VALUE);
	});

	it('accounts for every mounted way of signing in', () => {
		const mounted = elysia.routes
			.map((route) => `${route.method} ${route.path}`)
			.filter((key) => /^(POST|GET) \/ui\/:uid\//.test(key))
			.filter(isCandidate);

		expect(mounted.length).toBeGreaterThan(0);
		// Listed together, so adding a route names every gap at once rather than one per run.
		expect(mounted.filter((key) => !(key in SIGN_IN_ROUTES))).toEqual([]);
	});
});

/*
 * The interaction surface also serves pages and notices; only the routes that can conclude an
 * authentication are in scope. A new one lands here and fails the guard above until it is
 * classified.
 */
function isCandidate(key: string) {
	return /(login|totp|federation|registration|consent|abort)/.test(key);
}
