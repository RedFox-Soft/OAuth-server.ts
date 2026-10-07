import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent } from '../test_helper.ts';
import { resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { shaped } from 'test/shape.js';
import { Type } from '@sinclair/typebox';
import { createAdministrator, type AdminKind } from '../administrators.ts';

async function cookieFor(kind: AdminKind): Promise<string> {
	const user = await createAdministrator(
		kind,
		`shell-${kind}-${Date.now()}@x.io`
	);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

/**
 * @proves The console shell serves setup on a fresh instance and offers instance administration
 * only to a super administrator.
 */
describe('admin UI shell', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		// Cross-suite isolation: other admin specs (login_flow, interactions_bucket)
		// seed a super administrator into the shared in-memory admin bucket earlier in the
		// same `bun test` process. Drop the cached store singletons so this spec
		// sees a genuinely empty admin bucket before asserting on first-run setup.
		resetAdminMemoryStores();
	});

	it('serves the setup screen when no super administrator exists', async () => {
		const res = await agent.admin.get();
		const html = shaped(Type.String(), res.data);
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
	 * The audit page is a super-admin surface. renderAdminShell server-renders <Layout me={...}>, so
	 * the role gate on the nav entry is observable in the shell HTML without a built bundle — the
	 * bundle is deliberately absent under test (versionedAsset falls back for exactly that reason),
	 * so asserting on public/admin.js only ever passed on a locally built artifact.
	 *
	 * The sessions are minted here rather than in beforeAll because the first test above must see an
	 * admin bucket with no super administrator in it.
	 *
	 * This covers the nav gate only; the API's own scoping for a non-super-admin is pinned in
	 * audit_group_scope.spec.ts, which is where it actually matters.
	 *
	 * Audit moved out of the super-admin-only block with group ownership: it is scope-filtered rather
	 * than refused, so every administrator sees the entry and reads their own groups' history. What the
	 * shell must still withhold is the instance itself.
	 */
	it('offers instance administration in the shell only to a super administrator', async () => {
		const forbidden = await agent.admin.api.audit.get({ query: {} });
		expect(forbidden.status).toBe(401);

		const superAdmin = await agent.admin.get({
			headers: { cookie: await cookieFor('super') }
		});
		const superShell = shaped(Type.String(), superAdmin.data);
		expect(superShell).toContain('Settings');
		expect(superShell).toContain('Keys');

		const projectAdmin = await agent.admin.get({
			headers: { cookie: await cookieFor('plain') }
		});
		const shell = shaped(Type.String(), projectAdmin.data);
		expect(shell).not.toContain('Settings');
		expect(shell).not.toContain('Faults');
		// ...but the tenant's own surfaces are offered, including the two this feature unblocked.
		expect(shell).toContain('Groups');
		expect(shell).toContain('Audit');
	});
});
