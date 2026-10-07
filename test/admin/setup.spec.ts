import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { adminSetup, hasSuperAdmin } from 'lib/admin/auth/setup.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { isSuperAdmin, superAdminIds } from 'lib/admin/super_admins.ts';
import { present } from 'test/shape.js';

const app = new Elysia().use(adminSetup);
const client = treaty(app);

/**
 * @proves First-run setup creates the first super administrator and then closes permanently.
 */
describe('first-run setup', () => {
	// This spec asserts a clean admin bucket (no super administrator yet); reset the
	// process-wide store singletons so users seeded by earlier specs in the same
	// `bun test` run don't leak in.
	beforeEach(async () => {
		resetAdminMemoryStores();
		await ensureAdminSeed();
	});

	it('creates the first super administrator then hard-gates', async () => {
		expect(await hasSuperAdmin()).toBe(false);
		const first = await client.admin.api.setup.post({
			email: 'root@x.io',
			password: 'correct horse battery'
		});
		expect(first.status).toBe(201);
		const user = await getUserStore(ADMIN_BUCKET_ID).findByEmail('root@x.io');
		expect(await isSuperAdmin(present(user, 'user')._id)).toBe(true);

		const second = await client.admin.api.setup.post({
			email: 'evil@x.io',
			password: 'nope nope nope'
		});
		expect(second.status).toBe(409);
		expect(await hasSuperAdmin()).toBe(true);
	});

	/*
	 * The check that setup is still open and the creation it guards sit either side of a password hash,
	 * so two requests arriving together both found it open. Whoever raced the operator at first boot
	 * ended up a silent second super administrator rather than a visible refusal.
	 */
	it('creates exactly one super administrator when two setups arrive at once', async () => {
		const results = await Promise.all([
			client.admin.api.setup.post({
				email: 'operator@x.io',
				password: 'correct horse battery'
			}),
			client.admin.api.setup.post({
				email: 'racer@x.io',
				password: 'another long password'
			})
		]);

		expect(await superAdminIds()).toHaveLength(1);
		expect(results.map((r) => r.status).sort()).toEqual([201, 409]);
	});
});
