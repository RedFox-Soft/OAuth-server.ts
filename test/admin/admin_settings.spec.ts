import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { adminUserRoutes } from 'lib/admin/users/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	adminSessionStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';

/*
 * `normalize: false` because that is how lib/index.ts constructs the real app, and this suite has an
 * assertion that depends on it: with normalization on — Elysia's default, and what the other admin
 * specs get by building a bare instance — an undeclared body field is stripped before validation, so
 * a schema that refuses it looks identical to one that accepts and ignores it.
 */
const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(adminUserRoutes);
const client = treaty(app);

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

async function sessionCookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${unique(roles.join('-'))}@x.io`,
		'hash',
		roles
	);
	const session = await sessionFor(user);
	return { cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`, userId: user._id };
}

describe('admin bucket settings', () => {
	let admin: { cookie: string; userId: string };

	beforeEach(async () => {
		await ensureAdminSeed();
		admin = await sessionCookieFor(['super_admin']);
		await getBucketStore().update(ADMIN_BUCKET_ID, { totpRequired: false });
	});

	it('reports the reserved bucket defaulting to no second factor', async () => {
		const res = await client.admin.api.admins.settings.get({
			headers: { cookie: admin.cookie }
		});
		expect(res.status).toBe(200);
		expect(res.data).toEqual({ totpRequired: false });
	});

	it('turns the second factor on and reads it back', async () => {
		const patched = await client.admin.api.admins.settings.patch(
			{ totpRequired: true },
			{ headers: { cookie: admin.cookie } }
		);
		expect(patched.status).toBe(200);
		expect(patched.data).toEqual({ totpRequired: true });

		const read = await client.admin.api.admins.settings.get({
			headers: { cookie: admin.cookie }
		});
		expect(read.data).toEqual({ totpRequired: true });

		// Written to the bucket record itself — one source of truth, no shadow copy.
		expect((await getBucketStore().find(ADMIN_BUCKET_ID))?.totpRequired).toBe(
			true
		);
	});

	it('turns it back off', async () => {
		await client.admin.api.admins.settings.patch(
			{ totpRequired: true },
			{ headers: { cookie: admin.cookie } }
		);
		const off = await client.admin.api.admins.settings.patch(
			{ totpRequired: false },
			{ headers: { cookie: admin.cookie } }
		);
		expect(off.data).toEqual({ totpRequired: false });
	});

	/*
	 * `/admin/api/admins/:id` is a sibling of this path and matches a single segment, so without the
	 * static route winning, a PATCH here would be read as "update the administrator whose id is
	 * `settings`". The two routes answer differently enough that this is worth pinning rather than
	 * trusting the router's precedence to stay as it is.
	 */
	it('does not collide with the per-administrator route', async () => {
		const patched = await client.admin.api.admins.settings.patch(
			{ totpRequired: true },
			{ headers: { cookie: admin.cookie } }
		);
		expect(patched.status).toBe(200);
		// The per-admin route would have answered 404 for a user called `settings`, or 422 for a body
		// carrying neither `roles` nor `active`.
		expect(patched.data).toEqual({ totpRequired: true });
		expect(await getUserStore(ADMIN_BUCKET_ID).find('settings')).toBeNull();
	});

	it('refuses a project administrator', async () => {
		const weaker = await sessionCookieFor(['project_admin']);

		const read = await client.admin.api.admins.settings.get({
			headers: { cookie: weaker.cookie }
		});
		expect(read.status).toBe(403);

		const patched = await client.admin.api.admins.settings.patch(
			{ totpRequired: true },
			{ headers: { cookie: weaker.cookie } }
		);
		expect(patched.status).toBe(403);
		expect((await getBucketStore().find(ADMIN_BUCKET_ID))?.totpRequired).toBe(
			false
		);
	});

	it('refuses an unauthenticated caller', async () => {
		expect((await client.admin.api.admins.settings.get()).status).toBe(401);

		const patched = await client.admin.api.admins.settings.patch({
			totpRequired: true
		});
		expect(patched.status).toBe(401);
		expect((await getBucketStore().find(ADMIN_BUCKET_ID))?.totpRequired).toBe(
			false
		);
	});

	it('records the change against the actor', async () => {
		await client.admin.api.admins.settings.patch(
			{ totpRequired: true },
			{ headers: { cookie: admin.cookie } }
		);

		const { entries } = await adminAuditStore.list({
			targetType: 'UserBucket',
			targetId: ADMIN_BUCKET_ID
		});
		const entry = entries.find((e) => e.action === 'admin.settings.update');
		expect(entry).toBeDefined();
		expect(entry?.actorId).toBe(admin.userId);
		// Field names, never values — the trail's standing rule.
		expect(entry?.attributes).toContain('totpRequired');
	});

	/*
	 * The reason this endpoint carries one field and not the bucket's whole settings surface.
	 * `emailVerificationRequired` is a console brick: both admin-creation paths write `verified: false`
	 * and no verification mail is ever sent for this bucket, so accepting it here would let a
	 * super-admin lock every administrator out with one PATCH.
	 */
	it('accepts no other bucket setting', async () => {
		const res = await client.admin.api.admins.settings.patch(
			{
				totpRequired: true,
				emailVerificationRequired: true,
				registrationOpen: true,
				passwordLogin: false
			} as never,
			{ headers: { cookie: admin.cookie } }
		);
		expect(res.status).toBe(422);

		const bucket = await getBucketStore().find(ADMIN_BUCKET_ID);
		expect(bucket?.emailVerificationRequired).toBe(false);
		expect(bucket?.registrationOpen).toBe(false);
		expect(bucket?.passwordLogin).toBe(true);
	});
});
