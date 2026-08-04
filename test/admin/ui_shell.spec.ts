import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent } from '../test_helper.ts';
import {
	adminSessionStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

async function cookieFor(roles: string[]): Promise<string> {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`shell-${roles.join('-')}-${Date.now()}@x.io`,
		'hash',
		roles
	);
	const session = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

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
	 * The audit page is a super-admin surface. renderAdminShell server-renders <Layout me={...}>, so
	 * the role gate on the nav entry is observable in the shell HTML without a built bundle — the
	 * bundle is deliberately absent under test (serverRender.bundleVersion falls back for exactly
	 * that reason), so asserting on public/admin.js only ever passed on a locally built artifact.
	 *
	 * The sessions are minted here rather than in beforeAll because the first test above must see an
	 * admin bucket with no super_admin in it.
	 *
	 * This covers the nav gate only; the API's own refusal for a non-super-admin is pinned in
	 * audit_routes.spec.ts, which is where it actually matters.
	 */
	it('offers the audit trail in the shell only to a super administrator', async () => {
		const forbidden = await agent.admin.api.audit.get({ query: {} });
		expect(forbidden.status).toBe(401);

		const superAdmin = await agent.admin.get({
			headers: { cookie: await cookieFor(['super_admin']) }
		});
		expect(superAdmin.data as unknown as string).toContain('Audit');

		const projectAdmin = await agent.admin.get({
			headers: { cookie: await cookieFor(['project_admin']) }
		});
		expect(projectAdmin.data as unknown as string).not.toContain('Audit');
	});
});
