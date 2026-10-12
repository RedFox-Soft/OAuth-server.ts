import { Elysia } from 'elysia';

import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { loadBucketForEdit, loadBucketForUsers } from '../buckets/access.js';
import { recordAdminAudit } from '../audit/record.js';
import { getBucketGroupStore, getUserStore } from '../../adapters/index.js';
import {
	MAX_END_USER_PAGE,
	type BucketGroup,
	type ProvisioningConnection,
	type UserBucket
} from '../../adapters/types.js';
import {
	applyGroupChange,
	assignGroupToConnection,
	BucketGroupError,
	createGroup,
	deleteGroup,
	loadGroup,
	walkHandOver,
	type BucketGroupActor,
	type HandOverWalk
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
		const ctx = assertAuth(admin);
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
		const ctx = assertAuth(admin);
		const bucket = await loadBucketForUsers(ctx, params.id);
		return present(await asAdmin(loadGroup(bucket, ADMIN, params.gid)));
	})
	.get(
		'/admin/api/buckets/:id/groups/:gid/members',
		async ({ admin, params, query }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const group = await asAdmin(loadGroup(bucket, ADMIN, params.gid));
			const page = {
				startIndex: Math.max(1, positiveInt(query.startIndex, 1)),
				count: Math.min(MAX_END_USER_PAGE, positiveInt(query.count, 100))
			};
			/*
			 * A search reads the user store, which matches by its own keys, narrowed to the group's members —
			 * so the total is the matching members', exact, and a page never holds a matching non-member.
			 */
			const q = query.q?.trim();
			if (q) {
				const { users, totalResults } = await getUserStore(bucket._id).query(
					{ search: q, memberOf: group._id },
					page,
					'email'
				);
				return {
					totalResults,
					members: users.map((user) => ({
						id: user._id,
						email: user.email,
						...(user.userName === undefined ? {} : { userName: user.userName })
					}))
				};
			}
			const store = getBucketGroupStore();
			const ids = await store.memberIds(group._id, page);
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
			const ctx = assertAuth(admin);
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
			const ctx = assertAuth(admin);
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
			const ctx = assertAuth(admin);
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
			const ctx = assertAuth(admin);
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
			const ctx = assertAuth(admin);
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
	/*
	 * Previewed, then confirmed (specs/084 R5), as a sign-in change is (specs/083): the first call answers a 409
	 * stating what the hand-over means and whom it would leave behind, and only a call with `confirm: true` and
	 * the preview's `expect` applies it. Every 409 here is answered before the audit entry, so nothing is
	 * recorded for a hand-over that was only described or refused.
	 */
	.post(
		'/admin/api/buckets/:id/groups/:gid/connection',
		async ({ admin, params, body, status }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			const group = await asAdmin(loadGroup(bucket, ADMIN, params.gid));
			const connection = await asAdmin(
				loadConnection(bucket, body.connectionId)
			);
			const walk = await asAdmin(walkHandOver(bucket, group, connection));
			const preview = handOverPreview(group, connection, walk);
			if (body.confirm !== true) {
				return status(409, {
					confirmationRequired: true as const,
					...preview
				});
			}
			/* Nothing to confirm: the people named have to leave the group, or come under the connection, first. */
			if (walk.foreign > 0) {
				return status(409, {
					error: 'admin_error' as const,
					message: `${walk.foreign} member${walk.foreign === 1 ? ' is' : 's are'} not managed by this connection`,
					...preview
				});
			}
			/* The consent is to the counts shown; a member who joined or left since is not covered by it. */
			if (!sameHandOver(body.expect, preview.expect)) {
				return status(409, {
					error: 'admin_error' as const,
					message:
						body.expect === undefined
							? 'confirm with the counts of the preview you reviewed (expect)'
							: 'what this hand-over affects changed since you reviewed it',
					...preview,
					confirmationRequired: true as const
				});
			}
			const updated = await asAdmin(
				assignGroupToConnection(bucket, group, connection, walk, () =>
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

interface HandOverExpect {
	connectionId: string;
	managed: number;
	foreign: number;
}

function handOverPreview(
	group: BucketGroup,
	connection: ProvisioningConnection,
	walk: HandOverWalk
): {
	consequences: string[];
	expect: HandOverExpect;
	blockers: HandOverWalk['blockers'];
} {
	const people = (n: number) => `${n} member${n === 1 ? '' : 's'}`;
	const consequences = [
		`From now on only the directory behind "${connection.displayName}" can change "${group.displayName}": administrators can no longer rename it, delete it or change who is in it, and this cannot be undone here.`,
		`Relying parties keep seeing the group as "${group.displayName}" in the groups claim until the directory renames it.`,
		walk.managed > 0
			? `${people(walk.managed)} the connection already manages ${walk.managed === 1 ? 'stays' : 'stay'} in the group.`
			: 'The group has no member the connection manages.'
	];
	if (walk.foreign > 0) {
		consequences.push(
			`${people(walk.foreign)} ${walk.foreign === 1 ? 'is' : 'are'} not managed by this connection, so the group cannot be handed over until ${walk.foreign === 1 ? 'that person leaves' : 'they leave'} the group or ${walk.foreign === 1 ? 'is' : 'are'} handed to the connection.`
		);
	}
	return {
		consequences,
		expect: {
			connectionId: connection._id,
			managed: walk.managed,
			foreign: walk.foreign
		},
		blockers: walk.blockers
	};
}

function sameHandOver(
	given: HandOverExpect | undefined,
	fresh: HandOverExpect
): boolean {
	return (
		given !== undefined &&
		given.connectionId === fresh.connectionId &&
		given.managed === fresh.managed &&
		given.foreign === fresh.foreign
	);
}
