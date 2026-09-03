import { describe, it, expect } from 'bun:test';

import { elysia } from '../../lib/index.ts';
import { ApplicationConfig } from '../../lib/configs/application.ts';
import {
	alwaysAvailablePrefixes,
	alwaysAvailableRoutes,
	classifyRoutePattern,
	corsClassForPattern,
	corsMethodsForPath,
	corsRoutes,
	gatedRoutes,
	rateClassForPattern,
	rateClassForRequest,
	rateRoutes
} from '../../lib/consts/route_classification.ts';

// The two-way drift guard. Behavioural specs prove the 15 known gated endpoints refuse correctly;
// only this one can catch endpoint number 16 being mounted with no classification at all, which is
// the failure mode the whole feature exists to prevent.
describe('route classification', () => {
	const mounted = elysia.routes.map((route) => ({
		method: route.method,
		path: route.path
	}));

	const key = (r: { method: string; path: string }) => `${r.method} ${r.path}`;

	it('classifies every mounted route exactly once', () => {
		const unclassified = mounted
			.filter(
				(route) => classifyRoutePattern(route.method, route.path) === undefined
			)
			.map(key);

		expect(unclassified).toEqual([]);
	});

	it('declares no entry for a route the server does not serve', () => {
		const mountedKeys = new Set(mounted.map(key));

		const declared = [
			...gatedRoutes.map((r) => key(r)),
			...alwaysAvailableRoutes.map((r) => key(r))
		];

		const stale = declared.filter((k) => !mountedKeys.has(k));

		expect(stale).toEqual([]);
	});

	it('declares each route pattern only once across both classifications', () => {
		const declared = [
			...gatedRoutes.map((r) => key(r)),
			...alwaysAvailableRoutes.map((r) => key(r))
		];

		expect(declared.length).toBe(new Set(declared).size);
	});

	// A flag that is absent from ApplicationConfig reads `undefined`, which is falsy — so a typo
	// here would silently refuse a working endpoint forever rather than failing loudly.
	it('governs every gated route with a flag that exists on ApplicationConfig', () => {
		const unknown = gatedRoutes
			.filter((route) => !(route.flag in ApplicationConfig))
			.map((route) => `${key(route)} -> ${route.flag}`);

		expect(unknown).toEqual([]);
	});

	// The CORS mirror of the checks above. A route that is readable cross-origin by accident is the
	// failure this half exists to prevent, so the enumerated set is pinned exactly rather than merely
	// checked for staleness.
	describe('CORS classification', () => {
		const CORS_ENABLED = [
			'GET /.well-known/openid-configuration',
			'GET /jwks',
			'POST /token',
			'GET /userinfo',
			'POST /userinfo',
			'POST /token/revocation',
			'POST /par',
			'POST /device/auth'
		];

		it('declares no entry for a route the server does not serve', () => {
			const mountedKeys = new Set(mounted.map(key));

			const stale = corsRoutes
				.map((r) => key(r))
				.filter((k) => !mountedKeys.has(k));

			expect(stale).toEqual([]);
		});

		it('declares each route pattern only once', () => {
			const declared = corsRoutes.map((r) => key(r));

			expect(declared.length).toBe(new Set(declared).size);
		});

		it('exposes exactly the eight routes a browser may read cross-origin', () => {
			const enabled = mounted
				.filter(
					(route) => corsClassForPattern(route.method, route.path) !== 'none'
				)
				.map(key);

			expect(enabled.sort()).toEqual([...CORS_ENABLED].sort());
		});

		it('classifies every other mounted route as none', () => {
			const enabled = new Set(CORS_ENABLED);

			const leaked = mounted
				.filter((route) => !enabled.has(key(route)))
				.filter(
					(route) => corsClassForPattern(route.method, route.path) !== 'none'
				)
				.map(key);

			expect(leaked).toEqual([]);
		});

		// Preflight advertises Access-Control-Allow-Methods from this derivation, so a path that
		// serves two methods must report both or a browser will refuse the one it omitted.
		it('derives served methods from the same table', () => {
			expect(corsMethodsForPath('/userinfo').sort()).toEqual(['GET', 'POST']);
			expect(corsMethodsForPath('/token')).toEqual(['POST']);
			expect(corsMethodsForPath('/auth')).toEqual([]);
		});
	});

	/*
	 * The rate-limit mirror of the two above. Unlike the feature gate, an unclassified route here is not
	 * an error — it falls to `ordinary` and is still limited, because defaulting to unlimited would make
	 * forgetting this table equivalent to opting out of protection.
	 *
	 * That default is exactly why the three enumerated classes are pinned as exact sets rather than merely
	 * checked for staleness. The failure this half exists to catch is a new expensive endpoint being
	 * mounted and landing in `ordinary` unnoticed, or a cheap one being widened to `public` — neither of
	 * which any behavioural spec would report, because both still answer correctly.
	 */
	describe('rate limit classification', () => {
		// Unauthenticated, or expensive, or both: everything an attacker can make the server do real work
		// for without first proving anything.
		const STRICT = [
			'POST /token',
			'GET /auth',
			'POST /auth',
			'POST /par',
			'POST /reg',
			'POST /backchannel',
			'POST /device/auth',
			'GET /device',
			'POST /device',
			'POST /ui/:uid/login',
			'POST /ui/:uid/registration',
			'POST /ui/:uid/forgot-password',
			'POST /ui/:uid/totp',
			'POST /ui/:uid/totp/enroll',
			'POST /verify-email/code',
			'POST /verify-email/resend',
			'POST /reset-password',
			// Unauthenticated by construction — one is how the first super-admin comes to exist, the other
			// is how somebody invited into a group accepts. Both perform an account write.
			'POST /admin/api/setup',
			'POST /admin/api/invitations/accept'
		];

		// Cheap, public, and read by every client before it knows anything else about the deployment.
		const PUBLIC = [
			'GET /.well-known/openid-configuration',
			'GET /.well-known/oauth-protected-resource/mcp',
			'GET /.well-known/security.txt',
			'GET /jwks',
			'GET /public/*'
		];

		// The platform probes this every 30s. A refused health check takes the machine out of the proxy.
		const EXEMPT = ['GET /health'];

		it('declares no entry for a route the server does not serve', () => {
			const mountedKeys = new Set(mounted.map(key));

			const stale = rateRoutes
				.map((r) => key(r))
				.filter((k) => !mountedKeys.has(k));

			expect(stale).toEqual([]);
		});

		it('declares each route pattern only once', () => {
			const declared = rateRoutes.map((r) => key(r));

			expect(declared.length).toBe(new Set(declared).size);
		});

		it('applies the strict allowance to exactly the expensive unauthenticated surface', () => {
			const strict = mounted
				.filter(
					(route) => rateClassForPattern(route.method, route.path) === 'strict'
				)
				.map(key);

			expect(strict.sort()).toEqual([...STRICT].sort());
		});

		it('applies the loose allowance to exactly the cheap public surface', () => {
			const loose = mounted
				.filter(
					(route) => rateClassForPattern(route.method, route.path) === 'public'
				)
				.map(key);

			expect(loose.sort()).toEqual([...PUBLIC].sort());
		});

		it('exempts exactly the liveness probe', () => {
			const exempt = mounted
				.filter(
					(route) => rateClassForPattern(route.method, route.path) === 'exempt'
				)
				.map(key);

			expect(exempt.sort()).toEqual([...EXEMPT].sort());
		});

		it('classifies every other mounted route as ordinary', () => {
			const enumerated = new Set([...STRICT, ...PUBLIC, ...EXEMPT]);

			const misfiled = mounted
				.filter((route) => !enumerated.has(key(route)))
				.filter(
					(route) =>
						rateClassForPattern(route.method, route.path) !== 'ordinary'
				)
				.map(key);

			expect(misfiled).toEqual([]);
		});

		it('resolves every mounted route to a class, with none left undeclared', () => {
			const unresolved = mounted
				.filter(
					(route) => rateClassForPattern(route.method, route.path) === undefined
				)
				.map(key);

			expect(unresolved).toEqual([]);
		});

		/*
		 * The request-level resolver, which the pattern-level one above cannot stand in for: a request
		 * arrives as `/public/app.js`, not as the `/public/*` pattern, and preflights never reach the
		 * route table at all.
		 */
		describe('resolving an incoming request', () => {
			it('reads a static asset path through the prefix rather than the pattern', () => {
				expect(rateClassForRequest('GET', '/public/admin.js')).toBe('public');
				expect(rateClassForRequest('GET', '/public/nested/app.css')).toBe(
					'public'
				);
			});

			it('matches a :param pattern segment-wise', () => {
				expect(rateClassForRequest('POST', '/ui/abc123/login')).toBe('strict');
				expect(rateClassForRequest('GET', '/ui/abc123/consent')).toBe(
					'ordinary'
				);
			});

			// A preflight is answered before routing and costs almost nothing. Charging it to the strict
			// class would halve a browser client's real allowance and refuse it for requests it never sent.
			it('treats every preflight as public, whatever it is preflighting', () => {
				expect(rateClassForRequest('OPTIONS', '/token')).toBe('public');
				expect(rateClassForRequest('OPTIONS', '/ui/abc123/login')).toBe(
					'public'
				);
				expect(rateClassForRequest('OPTIONS', '/anything-at-all')).toBe(
					'public'
				);
			});

			it('falls back to ordinary for a path no entry names', () => {
				expect(rateClassForRequest('GET', '/_not_a_mounted_route')).toBe(
					'ordinary'
				);
			});

			it('does not let a prefix entry swallow a deeper unrelated path', () => {
				expect(rateClassForRequest('GET', '/publicity')).toBe('ordinary');
			});
		});
	});

	/*
	 * Every mounted route is accounted for by at least one mechanism, and no mechanism names a route that is
	 * not mounted.
	 *
	 * Compared as a union rather than as a sum of the three sizes, which is what this asserted until the
	 * federated sign-in arrived. A sum assumes the three are disjoint, and they are not: the federation legs
	 * are gated *and* sit under the always-available `/ui` prefix, which is legitimate — gatedRoutes is
	 * consulted first, so the gate wins — and made the arithmetic overcount by exactly those two routes.
	 * The union form still fails on an unclassified route, which is the failure this test exists for, and it
	 * additionally fails on a declared route the server does not serve.
	 */
	it('covers the whole mounted surface between gated, individual and prefix entries', () => {
		const prefixed = mounted.filter((route) =>
			alwaysAvailablePrefixes.some(
				(prefix) => route.path === prefix || route.path.startsWith(`${prefix}/`)
			)
		);

		const classified = new Set([
			...gatedRoutes.map(key),
			...alwaysAvailableRoutes.map(key),
			...prefixed.map(key)
		]);
		const mountedKeys = new Set(mounted.map(key));

		expect([...mountedKeys].filter((k) => !classified.has(k))).toEqual([]);
		expect([...classified].filter((k) => !mountedKeys.has(k))).toEqual([]);
	});
});
