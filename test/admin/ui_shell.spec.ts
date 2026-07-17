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
	});
});
