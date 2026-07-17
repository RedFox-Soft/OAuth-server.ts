import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { adminSetup, hasSuperAdmin } from 'lib/admin/auth/setup.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';

const app = new Elysia().use(adminSetup);
const client = treaty(app);

describe('first-run setup', () => {
	// This spec asserts a clean admin bucket (no super_admin yet); reset the
	// process-wide store singletons so users seeded by earlier specs in the same
	// `bun test` run don't leak in.
	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	it('creates the first super_admin then hard-gates', async () => {
		expect(await hasSuperAdmin()).toBe(false);
		const first = await client.admin.api.setup.post({
			email: 'root@x.io',
			password: 'correct horse battery'
		});
		expect(first.status).toBe(201);
		const user = await getUserStore(ADMIN_BUCKET_ID).findByEmail('root@x.io');
		expect(user?.roles).toEqual(['super_admin']);

		const second = await client.admin.api.setup.post({
			email: 'evil@x.io',
			password: 'nope nope nope'
		});
		expect(second.status).toBe(409);
		expect(await hasSuperAdmin()).toBe(true);
	});
});
