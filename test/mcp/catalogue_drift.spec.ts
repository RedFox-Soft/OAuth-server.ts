import { describe, it, expect } from 'bun:test';
import { Elysia } from 'elysia';

import {
	mcpCatalogue,
	excludedConsoleOperations,
	pathArgName
} from 'lib/mcp/catalogue.ts';
import { auditedAdminRoutes } from 'lib/consts/admin_audit_routes.ts';
import { adminApiRoutes } from 'lib/admin/routes.ts';

/*
 * The parity guard. FR-003 and FR-032 require that the console cannot gain an administrative operation
 * the agent surface neither publishes nor names as a deliberate exclusion — in either direction.
 *
 * Same technique as `test/admin/audit_route_classification.spec.ts`, for the reason that spec's own
 * comment gives: forgetting is the failure mode, so forgetting has to fail the suite.
 */

const mounted = new Elysia({ strictPath: true, normalize: false }).use(
	adminApiRoutes
);

const key = (r: { method: string; path: string }) => `${r.method} ${r.path}`;

const mountedApi = mounted.routes
	.filter((r) => r.path.startsWith('/admin/api'))
	.map((r) => ({ method: r.method, path: r.path }));

describe('MCP tool catalogue', () => {
	it('publishes 39 tools: 15 reads and 24 writes', () => {
		expect(mcpCatalogue.length).toBe(39);
		expect(mcpCatalogue.filter((t) => t.method === 'GET').length).toBe(15);
		expect(mcpCatalogue.filter((t) => t.method !== 'GET').length).toBe(24);
	});

	it('names exactly four exclusions', () => {
		// A fifth exclusion is a product decision, not a refactor: it must fail here until the
		// specification is updated to account for it.
		expect(excludedConsoleOperations.length).toBe(4);
	});

	it('accounts for every mounted /admin/api route, in both directions', () => {
		const published = new Set(mcpCatalogue.map(key));
		const excluded = new Set(excludedConsoleOperations.map(key));
		const mountedKeys = new Set(mountedApi.map(key));

		// Direction 1: nothing the console can do is unaccounted for.
		const unaccounted = [...mountedKeys].filter(
			(k) => !published.has(k) && !excluded.has(k)
		);
		expect(unaccounted).toEqual([]);

		// Direction 2: nothing is published or excluded that the console cannot do.
		const phantomTools = [...published].filter((k) => !mountedKeys.has(k));
		expect(phantomTools).toEqual([]);
		const phantomExclusions = [...excluded].filter((k) => !mountedKeys.has(k));
		expect(phantomExclusions).toEqual([]);

		// And the two sets are disjoint: an operation is published or withheld, never both.
		const both = [...published].filter((k) => excluded.has(k));
		expect(both).toEqual([]);
	});

	it('withholds project and bucket deletion, asserted by name', () => {
		// Asserted by name and not merely by the counts above, so the withholding cannot be undone by
		// an accidental catalogue addition that happens to keep the arithmetic right (FR-031).
		const published = new Set(mcpCatalogue.map(key));
		expect(published.has('DELETE /admin/api/projects/:id')).toBe(false);
		expect(published.has('DELETE /admin/api/buckets/:id')).toBe(false);
		expect(mcpCatalogue.some((t) => t.tool === 'project_delete')).toBe(false);
		expect(mcpCatalogue.some((t) => t.tool === 'bucket_delete')).toBe(false);

		const excluded = new Set(excludedConsoleOperations.map(key));
		expect(excluded.has('DELETE /admin/api/projects/:id')).toBe(true);
		expect(excluded.has('DELETE /admin/api/buckets/:id')).toBe(true);
	});

	it('classifies exactly eleven tools as high-consequence', () => {
		// Pinned as a count so FR-014's enumeration and this table cannot drift apart.
		const high = mcpCatalogue.filter((t) => t.consequence === 'high');
		expect(high.length).toBe(11);
		expect(high.map((t) => t.tool).sort()).toEqual([
			'admin_deactivate',
			'bucket_user_delete',
			'bucket_user_password_reset',
			'client_delete',
			'client_secret_rotate',
			'federation_identity_delete',
			'federation_provider_delete',
			'jwks_delete',
			'jwks_generate',
			'settings_update',
			'smtp_settings_update'
		]);
	});

	it('gives every write an audit action matching the audit table', () => {
		for (const tool of mcpCatalogue) {
			if (tool.method === 'GET') {
				expect(tool.action, tool.tool).toBeNull();
				expect(tool.consequence, tool.tool).toBe('read');
				continue;
			}
			expect(tool.action, tool.tool).not.toBeNull();
			expect(tool.consequence, tool.tool).not.toBe('read');

			// The action must be declared by the audit table for the SAME (method, path) — not merely
			// exist somewhere in it.
			const audited = auditedAdminRoutes.find((r) => r.action === tool.action);
			if (!audited) {
				throw new Error(`${tool.tool}: action not declared by the audit table`);
			}
			expect(key(audited), tool.tool).toBe(key(tool));
		}
	});

	it('has unique, well-formed tool names', () => {
		const names = mcpCatalogue.map((t) => t.tool);
		expect(new Set(names).size).toBe(names.length);
		for (const name of names) {
			expect(name, name).toMatch(/^[a-z]+(_[a-z]+)*$/);
		}
	});

	it('declares path params that match the path, and no others', () => {
		for (const tool of mcpCatalogue) {
			const inPath = [...tool.path.matchAll(/:([a-zA-Z]+)/g)].map((m) => m[1]);
			expect(tool.pathParams, tool.tool).toEqual(inPath);
		}
	});

	/*
	 * A tool takes one flat argument object, so two different things cannot share an argument name —
	 * one silently wins and the other is dropped.
	 *
	 * Not hypothetical. `federation_provider_create` posts to `/admin/api/buckets/:id/federation` while
	 * its body carries the provider's own `id`, so the provider id vanished and every call failed
	 * validation. `pathArgs` renames the path parameter; this is what stops the next such route from
	 * shipping broken.
	 */
	it('gives every argument of a tool a distinct name', () => {
		for (const tool of mcpCatalogue) {
			const names = [
				...tool.pathParams.map((p) => pathArgName(tool, p)),
				...Object.keys(
					(tool.querySchema?.properties ?? {}) as Record<string, unknown>
				),
				...Object.keys(
					(tool.bodySchema?.properties ?? {}) as Record<string, unknown>
				)
			];
			const duplicates = names.filter((n, i) => names.indexOf(n) !== i);
			expect(
				duplicates,
				`${tool.tool}: these arguments collide, so one would be dropped — alias the path parameter with pathArgs`
			).toEqual([]);
		}
	});

	it('aliases only path params that actually collide', () => {
		for (const tool of mcpCatalogue) {
			for (const [param, alias] of Object.entries(tool.pathArgs ?? {})) {
				// An alias for a parameter the path does not declare is dead configuration.
				expect(
					tool.pathParams,
					`${tool.tool}: aliases unknown param`
				).toContain(param);
				const bodyProps = Object.keys(
					(tool.bodySchema?.properties ?? {}) as Record<string, unknown>
				);
				expect(
					bodyProps,
					`${tool.tool}: aliases ${param} to ${alias} but nothing collides with it`
				).toContain(param);
			}
		}
	});

	/*
	 * A tool whose body is an open map gets an open input schema, so it must have no path parameters —
	 * otherwise an arbitrary key could collide with one and change which entity is addressed. Only
	 * `settings_update` is open today; this is what keeps that true.
	 */
	it('never opens the schema of a tool that has path parameters', () => {
		for (const tool of mcpCatalogue) {
			const openBody =
				tool.bodySchema !== null &&
				Object.keys((tool.bodySchema.properties ?? {}) as object).length === 0;
			if (!openBody) continue;
			expect(
				tool.pathParams,
				`${tool.tool}: an open body schema plus path parameters would let a body key shadow a path segment`
			).toEqual([]);
		}
	});

	// FR-002's second sentence: the allow-list is only meaningful if no tool can be talked into
	// addressing an arbitrary route. Nothing may accept a path, method or body passthrough.
	it('offers no generic passthrough', () => {
		const forbidden = ['path', 'method', 'url', 'route', 'body', 'headers'];
		for (const tool of mcpCatalogue) {
			expect(tool.path.startsWith('/admin/api/'), tool.tool).toBe(true);
			// A literal declaration form, not a wildcard or a caller-supplied segment.
			expect(tool.path, tool.tool).not.toContain('*');

			const props = Object.keys(
				(tool.bodySchema?.properties ?? {}) as Record<string, unknown>
			);
			for (const f of forbidden) {
				expect(props, `${tool.tool} accepts a ${f} field`).not.toContain(f);
			}
		}
	});

	it('summarises every tool, so an agent can choose without reading source', () => {
		for (const tool of mcpCatalogue) {
			expect(tool.summary.length, tool.tool).toBeGreaterThan(30);
		}
	});
});
