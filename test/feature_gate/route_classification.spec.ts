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
	gatedRoutes
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

	it('covers the whole mounted surface between gated, individual and prefix entries', () => {
		const prefixed = mounted.filter((route) =>
			alwaysAvailablePrefixes.some(
				(prefix) => route.path === prefix || route.path.startsWith(`${prefix}/`)
			)
		);

		expect(
			gatedRoutes.length + alwaysAvailableRoutes.length + prefixed.length
		).toBe(mounted.length);
	});
});
