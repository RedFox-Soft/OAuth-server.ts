import { describe, it, expect } from 'bun:test';

import { elysia } from '../../lib/index.ts';
import { buildDocsExport } from 'lib/docs_export/build.ts';
import { SETTINGS_CATALOG } from 'lib/admin/settings/catalog.ts';
import { mcpCatalogue, excludedConsoleOperations } from 'lib/mcp/catalogue.ts';
import { auditedAdminRoutes } from 'lib/consts/admin_audit_routes.ts';
import { ADDON_SEAMS } from 'lib/addon/seams.ts';
import {
	alwaysAvailablePrefixes,
	alwaysAvailableRoutes,
	gatedRoutes
} from 'lib/consts/route_classification.ts';

/*
 * The website renders its Reference section from this export and nothing else. Every table the
 * server already holds as data must arrive complete, and the result must survive JSON — TypeBox
 * schemas carry symbol keys, and a Buffer or a function anywhere would turn into `{}` or vanish.
 */
describe('documentation export', () => {
	const out = buildDocsExport({
		version: '0.0.0-test',
		generatedAt: '2026-09-02T00:00:00.000Z'
	});

	it('is versioned and stamped', () => {
		expect(out.schemaVersion).toBe(1);
		expect(out.version).toBe('0.0.0-test');
		expect(out.generatedAt).toBe('2026-09-02T00:00:00.000Z');
	});

	it('round-trips through JSON unchanged', () => {
		expect(JSON.parse(JSON.stringify(out))).toEqual(out);
	});

	it('exports every catalogued setting with its prose and its current value', () => {
		const keys = out.settings.entries.map((e) => e.key).sort();
		expect(keys).toEqual(SETTINGS_CATALOG.map((d) => d.key).sort());
		for (const entry of out.settings.entries) {
			expect(entry.description.length).toBeGreaterThan(20);
			expect(entry.summary.length).toBeGreaterThan(0);
			expect(entry).toHaveProperty('value');
			expect(out.settings.domains.map((d) => d.id)).toContain(entry.domain);
		}
	});

	it('exports every classified protocol route with its flag, CORS class and rate class', () => {
		expect(out.endpoints.length).toBe(
			gatedRoutes.length + alwaysAvailableRoutes.length
		);
		for (const endpoint of out.endpoints) {
			expect(['open', 'client-based', 'none']).toContain(endpoint.cors);
			expect(['strict', 'ordinary', 'public', 'exempt']).toContain(
				endpoint.rate
			);
		}
		expect(out.endpoints.filter((e) => e.flag === null).length).toBe(
			alwaysAvailableRoutes.length
		);
		expect(out.alwaysAvailablePrefixes).toEqual([...alwaysAvailablePrefixes]);
	});

	// The mounted route set is the truth the classification tables are guarded against; the export
	// must not be able to name a route the server does not serve.
	it('names only routes the server mounts', () => {
		const mounted = new Set(elysia.routes.map((r) => `${r.method} ${r.path}`));
		for (const endpoint of out.endpoints) {
			expect(mounted.has(`${endpoint.method} ${endpoint.path}`)).toBe(true);
		}
	});

	it('exports the whole MCP tool catalogue with serialisable schemas', () => {
		expect(out.mcp.tools.length).toBe(mcpCatalogue.length);
		for (const tool of out.mcp.tools) {
			expect(tool.summary.length).toBeGreaterThan(0);
			if (tool.bodySchema !== null) {
				expect(tool.bodySchema).toHaveProperty('type');
			}
		}
		expect(out.mcp.excluded.length).toBe(excludedConsoleOperations.length);
	});

	it('exports the audited admin routes and the addon seams', () => {
		expect(out.adminApi.audited.length).toBe(auditedAdminRoutes.length);
		expect(out.addonSeams).toEqual([...ADDON_SEAMS]);
	});

	it('exports the environment inventory', () => {
		expect(out.environment.map((v) => v.name)).toContain('ISSUER');
	});
});
