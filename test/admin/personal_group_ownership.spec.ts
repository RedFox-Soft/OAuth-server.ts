import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { createAdminSession } from 'lib/admin/auth/session.ts';
import { groupRoutes } from 'lib/admin/groups/routes.ts';
import { scopeRoutes } from 'lib/admin/scope/routes.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	getGroupStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { answered } from './answered.ts';

/*
 * A personal group may be shared, so an administrator can be a member of somebody else's. Which one is
 * *theirs* was answered by "a personal group they are a member of", and once they belonged to two the
 * answer was whichever the store returned first — an older account's group, since stores return in
 * insertion order. Someone who added a colleague to their own personal group became that colleague's
 * default scope at every sign-in, so the colleague's new projects, clients and buckets were created in
 * the other person's group, where that person could administer them.
 */

const app = new Elysia().use(resolveAdmin).use(groupRoutes).use(scopeRoutes);
const client = treaty(app);

function email(prefix: string): string {
	return `${prefix}-${Math.random().toString(36).slice(2)}@x.io`;
}

async function account() {
	return getUserStore(ADMIN_BUCKET_ID).create(email('adm'), 'hash', [
		'project_admin'
	]);
}

/* An older administrator who adds a newer one to their own personal group. */
async function pulledIn() {
	const older = await account();
	const olderSession = await sessionFor(older);
	const olderGroup = (await getGroupStore().listByMember(older._id))[0];

	const newer = await account();
	const newerGroup = await ensurePersonalGroup(newer._id, newer.email);

	await client.admin.api
		.groups({ id: olderGroup._id })
		.members.post(
			{ userId: newer._id, role: 'member' },
			{ headers: { cookie: `${ADMIN_SESSION_COOKIE}=${olderSession._id}` } }
		);
	return { newer, newerGroup, olderGroup };
}

/**
 * @proves An administrator's own personal group stays their default scope after they are added to
 * somebody else's.
 */
describe("an administrator added to another's personal group", () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('still signs in to their own personal group', async () => {
		const { newer, newerGroup } = await pulledIn();

		const session = await createAdminSession({
			userId: newer._id,
			bucketId: ADMIN_BUCKET_ID,
			tokens: {}
		});

		expect(session.activeGroupId).toBe(newerGroup._id);
	});

	it('falls back to their own personal group when the session names none they belong to', async () => {
		const { newer, newerGroup } = await pulledIn();
		const session = await adminSessionStore.create({
			userId: newer._id,
			bucketId: ADMIN_BUCKET_ID,
			activeGroupId: 'a-group-that-is-gone',
			tokens: {},
			ttlSeconds: 60,
			absoluteTtlSeconds: 3600
		});

		const scope = answered(
			(
				await client.admin.api.scope.get({
					headers: { cookie: `${ADMIN_SESSION_COOKIE}=${session._id}` }
				})
			).data
		);

		expect(scope.activeGroupId).toBe(newerGroup._id);
	});

	it('is given a personal group of their own even when they already belong to another', async () => {
		const older = await account();
		const olderSession = await sessionFor(older);
		const olderGroup = (await getGroupStore().listByMember(older._id))[0];
		const newer = await account();
		await client.admin.api
			.groups({ id: olderGroup._id })
			.members.post(
				{ userId: newer._id, role: 'member' },
				{ headers: { cookie: `${ADMIN_SESSION_COOKIE}=${olderSession._id}` } }
			);

		const own = await ensurePersonalGroup(newer._id, newer.email);

		expect(own._id).not.toBe(olderGroup._id);
		expect(own.members[0]?.userId).toBe(newer._id);
	});
});
