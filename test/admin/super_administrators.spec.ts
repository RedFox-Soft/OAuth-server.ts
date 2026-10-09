import { describe, it, beforeAll, expect } from 'bun:test';

import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	ADMIN_SESSION_COOKIE,
	SUPER_ADMINS_GROUP_ID
} from 'lib/admin/consts.ts';
import { isSuperAdmin } from 'lib/admin/super_admins.ts';
import bootstrap from '../test_helper.js';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import { admin } from '../provisioning/helpers.ts';
import { shaped } from '../shape.ts';
import { Type } from '@sinclair/typebox';

async function signedIn(kind: AdminKind) {
	const user = await createAdministrator(kind);
	return {
		userId: user._id,
		cookie: `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`
	};
}

/**
 * @proves The instance-wide privilege is membership of Super administrators and nothing else: a member may do
 * what only a super administrator may, anyone else is refused; only a super administrator grants or withdraws
 * it, by operations of their own that are audited; creating an administrator never grants it; the last active
 * member cannot be removed; and the group itself cannot be reached through the routes that manage ordinary
 * groups (spec 071, User Story 7).
 */
describe('Super administrators', () => {
	let root: { userId: string; cookie: string };

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		await ensureAdminSeed();
		root = await signedIn('super');
	});

	it('lets a member perform an instance-wide operation', async () => {
		const res = await admin('GET', '/admin/api/admins', root.cookie);

		expect(res.status).toBe(200);
	});

	it('refuses an instance-wide operation to an administrator who is not a member', async () => {
		const plain = await signedIn('plain');

		const res = await admin('GET', '/admin/api/admins', plain.cookie);

		expect(res.status).toBe(403);
	});

	it('takes effect on the next request once granted, and records the grant', async () => {
		const target = await signedIn('plain');

		const granted = await admin(
			'POST',
			`/admin/api/admins/${target.userId}/super-admin`,
			root.cookie
		);
		const next = await admin('GET', '/admin/api/admins', target.cookie);
		const trail = await admin(
			'GET',
			`/admin/api/audit?targetId=${target.userId}&action=admin.superadmin.grant`,
			root.cookie
		);

		expect(granted.status).toBe(200);
		expect(next.status).toBe(200);
		expect((trail.json.entries as unknown[]).length).toBe(1);
	});

	it('takes effect on the next request once withdrawn, and records the withdrawal', async () => {
		const target = await signedIn('super');

		const withdrawn = await admin(
			'DELETE',
			`/admin/api/admins/${target.userId}/super-admin`,
			root.cookie
		);
		const next = await admin('GET', '/admin/api/admins', target.cookie);
		const trail = await admin(
			'GET',
			`/admin/api/audit?targetId=${target.userId}&action=admin.superadmin.withdraw`,
			root.cookie
		);

		expect(withdrawn.status).toBe(200);
		expect(next.status).toBe(403);
		expect((trail.json.entries as unknown[]).length).toBe(1);
	});

	it('refuses a grant made by an administrator who is not a member', async () => {
		const plain = await signedIn('plain');
		const target = await signedIn('plain');

		const res = await admin(
			'POST',
			`/admin/api/admins/${target.userId}/super-admin`,
			plain.cookie
		);

		expect(res.status).toBe(403);
		expect(await isSuperAdmin(target.userId)).toBe(false);
	});

	it('refuses a withdrawal made by an administrator who is not a member', async () => {
		const plain = await signedIn('plain');

		const res = await admin(
			'DELETE',
			`/admin/api/admins/${root.userId}/super-admin`,
			plain.cookie
		);

		expect(res.status).toBe(403);
		expect(await isSuperAdmin(root.userId)).toBe(true);
	});

	it('never makes a newly created administrator a member', async () => {
		const res = await admin('POST', '/admin/api/admins', root.cookie, {
			email: `new-${Math.random()}@x.io`,
			password: 'a password that is long enough'
		});

		expect(res.status).toBe(201);
		expect(res.json.superAdmin).toBe(false);
		expect(await isSuperAdmin(res.json._id as string)).toBe(false);
	});

	it('cannot be read, renamed, deleted or joined through the group routes', async () => {
		const path = `/admin/api/groups/${SUPER_ADMINS_GROUP_ID}`;

		const statuses = [
			(await admin('GET', path, root.cookie)).status,
			(await admin('PATCH', path, root.cookie, { name: 'Mine' })).status,
			(await admin('DELETE', path, root.cookie)).status,
			(
				await admin('POST', `${path}/members`, root.cookie, {
					userId: root.userId,
					role: 'owner'
				})
			).status
		];

		expect(statuses).toEqual([404, 404, 404, 404]);
	});

	it('is neither listed among groups nor offered as a scope to work in', async () => {
		const groups = await admin('GET', '/admin/api/groups', root.cookie);
		const scope = await admin('GET', '/admin/api/scope', root.cookie);

		expect(
			shaped(Type.Array(Type.Object({ _id: Type.String() })), groups.body).some(
				(g) => g._id === SUPER_ADMINS_GROUP_ID
			)
		).toBe(false);
		expect(
			(scope.json.available as { id: string }[]).some(
				(g) => g.id === SUPER_ADMINS_GROUP_ID
			)
		).toBe(false);
	});

	it('cannot be switched into', async () => {
		const res = await admin('PUT', '/admin/api/scope', root.cookie, {
			groupId: SUPER_ADMINS_GROUP_ID
		});

		expect(res.status).toBe(403);
	});
});
