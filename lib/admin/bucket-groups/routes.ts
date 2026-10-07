import { Elysia } from 'elysia';

import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { loadBucketForEdit, loadBucketForUsers } from '../buckets/access.js';
import { recordAdminAudit } from '../audit/record.js';
import { getBucketGroupStore, getUserStore } from '../../adapters/index.js';
import {
	MAX_END_USER_PAGE,
	type BucketGroup,
	type UserBucket
} from '../../adapters/types.js';
import {
	applyGroupChange,
	assignGroupToConnection,
	BucketGroupError,
	createGroup,
	deleteGroup,
	loadGroup,
	type BucketGroupActor
} from '../../bucket_groups/service.js';
import {
	loadConnection,
	ProvisioningError
} from '../../provisioning/service.js';
import nanoid from '../../helpers/nanoid.js';
import {
	AddBucketGroupMembersBody,
	AssignBucketGroupConnectionBody,
	BucketGroupMemberPageQuery,
	CreateBucketGroupBody,
	RenameBucketGroupBody
} from './schema.js';

/*
 * A bucket's groups of end users.
 *
 * Creating, renaming, deleting and handing a group to a connection change the bucket's own vocabulary, so
 * they need the bucket itself (`loadBucketForEdit`) — as declaring a role did. Changing who is in a group is
 * managing the bucket's users (`loadBucketForUsers`), as assigning a role to a user was. Both refuse the
 * administrators' bucket. Every write records audit-first: the service calls `record` after every refusal and
 * before the one write, so a refused request leaves no entry.
 */

const ADMIN: BucketGroupActor = { kind: 'admin' };

async function asAdmin<T>(operation: Promise<T>): Promise<T> {
	try {
		return await operation;
	} catch (error) {
		if (
			error instanceof BucketGroupError ||
			error instanceof ProvisioningError
		) {
			throw new AdminError(error.status, error.message, error.extra);
		}
		throw error;
	}
}

function scope(bucket: UserBucket) {
	return { targetScope: bucket._id, ownerGroupId: bucket.ownerGroupId };
}

async function present(group: BucketGroup) {
	return {
		id: group._id,
		displayName: group.displayName,
		...(group.externalId === undefined ? {} : { externalId: group.externalId }),
		...(group.provisionedBy === undefined
			? {}
			: { provisionedBy: group.provisionedBy }),
		memberCount: await getBucketGroupStore().memberCount(group._id),
		createdAt: group.createdAt.toISOString(),
		updatedAt: group.updatedAt.toISOString()
	};
}

function positiveInt(value: string | undefined, fallback: number): number {
	if (value === undefined) return fallback;
	const parsed = Number(value);
	if (!Number.isInteger(parsed) || parsed < 0) {
		throw new AdminError(
			422,
			'startIndex and count must be non-negative integers'
		);
	}
	return parsed;
}

export const bucketGroupRoutes = new Elysia({ name: 'admin-bucket-groups' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/buckets/:id/groups', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const bucket = await loadBucketForUsers(ctx, params.id);
		const groups: BucketGroup[] = [];
		for (let startIndex = 1; ; startIndex += MAX_END_USER_PAGE) {
			const page = await getBucketGroupStore().query(
				{ bucketId: bucket._id },
				{ startIndex, count: MAX_END_USER_PAGE }
			);
			groups.push(...page.groups);
			if (groups.length >= page.totalResults || page.groups.length === 0) break;
		}
		return { groups: await Promise.all(groups.map(present)) };
	})
	.get('/admin/api/buckets/:id/groups/:gid', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const bucket = await loadBucketForUsers(ctx, params.id);
		return present(await asAdmin(loadGroup(bucket, ADMIN, params.gid)));
	})
	.get(
		'/admin/api/buckets/:id/groups/:gid/members',
		async ({ admin, params, query }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const group = await asAdmin(loadGroup(bucket, ADMIN, params.gid));
			const store = getBucketGroupStore();
			const ids = await store.memberIds(group._id, {
				startIndex: Math.max(1, positiveInt(query.startIndex, 1)),
				count: Math.min(MAX_END_USER_PAGE, positiveInt(query.count, 100))
			});
			const users = new Map(
				(await getUserStore(bucket._id).findMany(ids)).map((u) => [u._id, u])
			);
			return {
				totalResults: await store.memberCount(group._id),
				members: ids.map((id) => {
					const user = users.get(id);
					return {
						id,
						email: user?.email ?? null,
						...(user?.userName === undefined ? {} : { userName: user.userName })
					};
				})
			};
		},
		{ query: BucketGroupMemberPageQuery }
	)
	.post(
		'/admin/api/buckets/:id/groups',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForEdit(ctx, params.id);
			/* Allocated here so the entry names the group that is about to exist. */
			const id = nanoid();
			const created = await asAdmin(
				createGroup(bucket, ADMIN, { id, displayName: body.displayName }, () =>
					recordAdminAudit(ctx, 'bucketgroup.create', id, {
						attributes: ['displayName'],
						...scope(bucket)
					})
				)
			);
			set.status = 201;
			return present(created);
		},
		{ body: CreateBucketGroupBody }
	)
	.patch(
		'/admin/api/buckets/:id/groups/:gid',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const group = await asAdmin(loadGroup(bucket, ADMIN, params.gid));
			const updated = await asAdmin(
				applyGroupChange(
					bucket,
					ADMIN,
					group,
					{ displayName: body.displayName },
					(parts) =>
						recordAdminAudit(ctx, 'bucketgroup.update', group._id, {
							attributes: parts.attributes,
							...scope(bucket)
						})
				)
			);
			return present(updated);
		},
		{ body: RenameBucketGroupBody }
	)
	.delete(
		'/admin/api/buckets/:id/groups/:gid',
		async ({ admin, params, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const group = await asAdmin(loadGroup(bucket, ADMIN, params.gid));
			await asAdmin(
				deleteGroup(bucket, ADMIN, group, () =>
					recordAdminAudit(ctx, 'bucketgroup.delete', group._id, scope(bucket))
				)
			);
			set.status = 204;
		}
	)
	.post(
		'/admin/api/buckets/:id/groups/:gid/members',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const group = await asAdmin(loadGroup(bucket, ADMIN, params.gid));
			const updated = await asAdmin(
				applyGroupChange(bucket, ADMIN, group, { add: body.userIds }, () =>
					/* Names only — the trail never carries the members themselves. */
					recordAdminAudit(ctx, 'bucketgroup.member.add', group._id, {
						attributes: ['members'],
						...scope(bucket)
					})
				)
			);
			return present(updated);
		},
		{ body: AddBucketGroupMembersBody }
	)
	.delete(
		'/admin/api/buckets/:id/groups/:gid/members/:uid',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const group = await asAdmin(loadGroup(bucket, ADMIN, params.gid));
			const updated = await asAdmin(
				applyGroupChange(bucket, ADMIN, group, { remove: [params.uid] }, () =>
					recordAdminAudit(ctx, 'bucketgroup.member.remove', group._id, {
						attributes: ['members'],
						...scope(bucket)
					})
				)
			);
			return present(updated);
		}
	)
	.post(
		'/admin/api/buckets/:id/groups/:gid/connection',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const group = await asAdmin(loadGroup(bucket, ADMIN, params.gid));
			const connection = await asAdmin(
				loadConnection(bucket, body.connectionId)
			);
			const updated = await asAdmin(
				assignGroupToConnection(bucket, group, connection, () =>
					recordAdminAudit(ctx, 'bucketgroup.connection.assign', group._id, {
						attributes: ['provisionedBy'],
						...scope(bucket)
					})
				)
			);
			return present(updated);
		},
		{ body: AssignBucketGroupConnectionBody }
	);
