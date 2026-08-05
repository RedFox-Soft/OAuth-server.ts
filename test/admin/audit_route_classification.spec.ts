import { describe, it, expect } from 'bun:test';

import { elysia } from '../../lib/index.ts';
import {
	auditedAdminRoutes,
	excludedAdminRoutes,
	auditRouteFor,
	isExcludedAdminRoute,
	AUDIT_ACTION_PATTERN
} from '../../lib/consts/admin_audit_routes.ts';

/*
 * The two-way drift guard for the audit trail's completeness. `audit_coverage.spec.ts` proves the 23
 * known operations record correctly; only this spec can catch operation number 24 being mounted with
 * no audit entry at all, which is the hole the constitution's "every state-changing admin action"
 * requirement exists to prevent.
 *
 * Same shape as test/feature_gate/route_classification.spec.ts, and for the same reason: forgetting is
 * the failure mode, so forgetting has to fail the suite.
 */
const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

describe('admin audit route classification', () => {
	const mounted = elysia.routes
		.map((route) => ({ method: route.method, path: route.path }))
		.filter(
			(route) =>
				MUTATING.has(route.method) && route.path.startsWith('/admin/api')
		);

	const key = (r: { method: string; path: string }) => `${r.method} ${r.path}`;

	it('classifies every mounted state-changing admin route', () => {
		const unclassified = mounted
			.filter(
				(route) =>
					auditRouteFor(route.method, route.path) === undefined &&
					!isExcludedAdminRoute(route.method, route.path)
			)
			.map(key);

		expect(unclassified).toEqual([]);
	});

	it('declares no entry for a route the server does not serve', () => {
		const mountedKeys = new Set(mounted.map(key));

		const stale = [
			...auditedAdminRoutes.map(key),
			...excludedAdminRoutes.map(key)
		].filter((k) => !mountedKeys.has(k));

		expect(stale).toEqual([]);
	});

	it('audits every mutating admin route except the one deliberate exclusion', () => {
		// Pinned exactly rather than merely checked for staleness: an operation quietly moved into the
		// exclusion list is indistinguishable from one that was never audited.
		expect(excludedAdminRoutes.map(key)).toEqual(['POST /admin/api/logout']);

		/*
		 * Counted exactly, and the numbers grow with the table: 23 + the four federation rows (three provider
		 * operations and one identity severance). A count that drifted upward silently would let an audited
		 * route be swapped for an unaudited one without either total changing.
		 */
		expect(auditedAdminRoutes).toHaveLength(27);
		expect(mounted).toHaveLength(28);
	});

	it('declares each route pattern only once', () => {
		const declared = auditedAdminRoutes.map(key);

		expect(declared.length).toBe(new Set(declared).size);
	});

	it('gives every route a unique action name following the convention', () => {
		const actions = auditedAdminRoutes.map((route) => route.action);

		expect(actions.length).toBe(new Set(actions).size);
		expect(actions.filter((a) => !AUDIT_ACTION_PATTERN.test(a))).toEqual([]);
	});

	it('resolves a target type for every declared action', () => {
		const missing = auditedAdminRoutes.filter(
			(route) => !route.targetType.trim()
		);

		expect(missing).toEqual([]);
	});
});
