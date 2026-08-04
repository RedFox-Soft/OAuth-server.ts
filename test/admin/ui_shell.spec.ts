import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent } from '../test_helper.ts';
import { resetAdminMemoryStores } from 'lib/adapters/index.ts';

describe('admin UI shell', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		// Cross-suite isolation: other admin specs (login_flow, interactions_bucket)
		// seed a super_admin into the shared in-memory admin bucket earlier in the
		// same `bun test` process. Drop the cached store singletons so this spec
		// sees a genuinely empty admin bucket before asserting on first-run setup.
		resetAdminMemoryStores();
	});

	it('serves the setup screen when no super_admin exists', async () => {
		const res = await agent.admin.get();
		const html = res.data as unknown as string;
		expect(res.response.headers.get('content-type')).toContain('text/html');
		expect(html).toContain('window.PROPS');
		expect(html).toContain('"needsSetup":true');
		// The bundle is served by staticPlugin under the '/public' prefix (with an
		// optional ?v= cache-buster); pointing elsewhere means the SPA never
		// hydrates (unstyled page).
		expect(html).toMatch(/src="\/public\/admin\.js(\?v=[^"]*)?"/);
		expect(html).not.toContain('src="/admin.js"');
	});

	/*
	 * The audit page is a super-admin surface, and the SPA decides what to render from `me.roles` in
	 * the injected props. The shell can only be checked this far here; the API's own refusal for a
	 * non-super-admin is pinned in audit_routes.spec.ts, which is where it actually matters.
	 */
	it('serves the audit trail only to a super administrator', async () => {
		const forbidden = await agent.admin.api.audit.get({ query: {} });
		expect(forbidden.status).toBe(401);

		const bundle = await agent.public['admin.js'].get();
		const source = bundle.data as unknown as string;
		expect(source).toContain('Audit trail');
		expect(source).toContain('/admin/api/audit');
	});
});
