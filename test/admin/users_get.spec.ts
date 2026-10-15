import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import { adminApiRoutes } from 'lib/admin/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import { shaped } from '../shape.ts';

async function call(
	method: 'GET' | 'POST',
	path: string,
	cookie: string,
	body?: unknown
) {
	const res = await adminApiRoutes.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: {
				cookie,
				...(body === undefined ? {} : { 'content-type': 'application/json' })
			},
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	return { status: res.status, body: (await res.json()) as unknown };
}

async function signedIn() {
	const admin = await createAdministrator('super');
	return {
		admin,
		cookie: `${ADMIN_SESSION_COOKIE}=${(await sessionFor(admin))._id}`
	};
}

async function bucket() {
	return (
		await getBucketStore().create({
			name: `get-${Math.random()}`,
			ownerGroupId: UNASSIGNED_GROUP_ID
		})
	)._id;
}

const Locked = Type.Object({
	lockedLocally: Type.Object({
		reason: Type.String(),
		by: Type.String(),
		byEmail: Type.Union([Type.String(), Type.Null()])
	})
});

/**
 * @proves An administrator opens one person and reads everything the page shows — their groups, whether a
 * password was set, and who locked them — and a person the bucket does not hold is not found.
 */
describe('reading one bucket user', () => {
	let cookie: string;

	beforeAll(async () => {
		await ensureAdminSeed();
		({ cookie } = await signedIn());
	});

	it('answers the person with the groups they are in', async () => {
		const b = await bucket();
		const user = await getUserStore(b).create('grouped@example.com', 'h', true);
		const group = shaped(
			Type.Object({ id: Type.String() }),
			(
				await call('POST', `/admin/api/projects/${b}/groups`, cookie, {
					displayName: 'Readers'
				})
			).body
		);
		await call(
			'POST',
			`/admin/api/projects/${b}/groups/${group.id}/members`,
			cookie,
			{ userIds: [user._id] }
		);

		const { status, body } = await call(
			'GET',
			`/admin/api/projects/${b}/users/${user._id}`,
			cookie
		);

		expect(status).toBe(200);
		expect(body).toHaveProperty('groups', [
			{ id: group.id, displayName: 'Readers' }
		]);
	});

	it('says a password was set for a person created with one', async () => {
		const b = await bucket();
		const created = shaped(
			Type.Object({ _id: Type.String() }),
			(
				await call('POST', `/admin/api/projects/${b}/users`, cookie, {
					email: 'with-password@example.com',
					password: 'a long enough password'
				})
			).body
		);

		const { body } = await call(
			'GET',
			`/admin/api/projects/${b}/users/${created._id}`,
			cookie
		);

		expect(body).toHaveProperty('passwordSet', true);
	});

	it('names the administrator who locked the person', async () => {
		const b = await bucket();
		const user = await getUserStore(b).create('locked@example.com', 'h', true);
		const locker = await signedIn();
		await call(
			'POST',
			`/admin/api/projects/${b}/users/${user._id}/lock`,
			locker.cookie,
			{ reason: 'suspected phishing' }
		);

		const { body } = await call(
			'GET',
			`/admin/api/projects/${b}/users/${user._id}`,
			cookie
		);

		const { lockedLocally } = shaped(Locked, body);
		expect(lockedLocally.byEmail).toBe(locker.admin.email);
		expect(lockedLocally.reason).toBe('suspected phishing');
	});

	it('answers no locker email once that administrator’s account is gone', async () => {
		const b = await bucket();
		const user = await getUserStore(b).create('orphan@example.com', 'h', true);
		const locker = await signedIn();
		await call(
			'POST',
			`/admin/api/projects/${b}/users/${user._id}/lock`,
			locker.cookie,
			{ reason: 'left the company' }
		);
		await getUserStore(ADMIN_BUCKET_ID).destroy(locker.admin._id);

		const { body } = await call(
			'GET',
			`/admin/api/projects/${b}/users/${user._id}`,
			cookie
		);

		expect(shaped(Locked, body).lockedLocally.byEmail).toBeNull();
	});

	it('answers 404 for a person the bucket does not hold', async () => {
		const b = await bucket();

		const { status } = await call(
			'GET',
			`/admin/api/projects/${b}/users/absent-user`,
			cookie
		);

		expect(status).toBe(404);
	});

	it('never answers the password hash or the authenticator secret', async () => {
		const b = await bucket();
		const user = await getUserStore(b).create('secret@example.com', 'h', true);
		await getUserStore(b).update(user._id, {
			totp: { secret: 'JBSWY3DPEHPK3PXP', enrolledAt: new Date(), lastStep: 0 }
		});

		const { body } = await call(
			'GET',
			`/admin/api/projects/${b}/users/${user._id}`,
			cookie
		);

		expect(body).not.toHaveProperty('password');
		expect(body).not.toHaveProperty('totp');
		expect(body).toHaveProperty('totpEnrolled', true);
	});
});
