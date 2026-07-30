import { describe, it, expect } from 'bun:test';

import { elysia } from '../../lib/index.ts';
import { ApplicationConfig } from '../../lib/configs/application.ts';
import {
	alwaysAvailablePrefixes,
	alwaysAvailableRoutes,
	classifyRoutePattern,
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
