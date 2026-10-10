import { Elysia } from 'elysia';
import {
	getProjectStore,
	getBucketStore,
	getContainerOwnershipStore,
	getProtectedResourceStore
} from '../../adapters/index.js';
import {
	assertAuth,
	assertActiveGroup,
	assertBucketAccess,
	assertGroupOwner,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import {
	CreateProjectBody,
	UpdateProjectBody,
	SetBucketBody,
	DeleteProjectQuery,
	MoveProjectOwnerBody
} from './schema.js';
import { deleteClientRecord } from '../clients/service.js';
import { cascadeForClient } from '../../helpers/cascade.js';
import {
	InvalidOriginError,
	normalizeOrigins
} from '../../helpers/cors_origin.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import {
	describeGroup,
	loadDestination,
	sourceGroupOf
} from '../ownership/destination.js';
import { loadProject } from './access.js';
import { recordAdminAudit } from '../audit/record.js';
import { Client } from '../../models/client.js';
import nanoid from '../../helpers/nanoid.js';
import {
	namespaceOf,
	namespaceOfProject,
	ROOT_NAMESPACE
} from '../../resources/namespace.js';
import {
	applyMove,
	DeclarationsConflict,
	planMove
} from '../resources/move.js';

/*
 * Normalizes a submitted origin list, or refuses the whole request. All-or-nothing on purpose: half a
 * list is a configuration an operator did not ask for, and the browser-facing consequence of a silently
 * dropped entry is an app that cannot reach the server.
 */
function validateCorsOrigins(origins: string[] | undefined) {
	if (origins === undefined) {
		return undefined;
	}
	try {
		return normalizeOrigins(origins);
	} catch (err) {
		if (err instanceof InvalidOriginError) {
			throw new AdminError(400, err.message);
		}
		throw err;
	}
}

/*
 * A repeated query parameter arrives as an array, a single one as a string, and an absent one as
 * undefined. Normalised here so the handler compares sets rather than three shapes — and `null` is
 * kept distinct from `[]`, because "consented to nothing" and "did not consent" are different
 * answers to the only question this parameter asks.
 */
function normalizeConsentedClients(
	value: string | string[] | undefined
): string[] | null {
	if (value === undefined) return null;
	return Array.isArray(value) ? value : [value];
}

/* Set equality, because the order the console listed them in is not part of what was consented to. */
function sameSet(a: readonly string[], b: readonly string[]): boolean {
	if (a.length !== b.length) return false;
	const other = new Set(b);
	return a.every((value) => other.has(value));
}

export const projectRoutes = new Elysia({ name: 'admin-projects' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			// The identifiers in the way, so an operator knows which declaration to remove or rename.
			return error instanceof DeclarationsConflict
				? { ...adminErrorBody(error), conflicts: error.conflicts }
				: adminErrorBody(error);
		}
	})
	.get('/admin/api/projects', async ({ admin }) => {
		const ctx = assertAuth(admin);
		const store = getProjectStore();
		/*
		 * Scope-filtered, not role-gated. A super administrator sees the instance; everyone else sees the
		 * group their console is pointed at — not every group they belong to, because the console has one
		 * active scope and a list mixing two tenants is the thing scope switching exists to prevent.
		 */
		const all = ctx.superAdmin
			? (await store.list()).filter((p) => p.type === 'regular')
			: (await store.listByGroup(ctx.activeGroupId)).filter(
					(p) => p.type === 'regular'
				);
		return all;
	})
	.post(
		'/admin/api/projects',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin);
			/*
			 * No role gate. Creating a project is what a project administrator signs in to do, and the
			 * authority that matters is membership of the group it will belong to — checked below, on the
			 * scope the caller is actually in.
			 */
			const ownerGroupId = assertActiveGroup(ctx);
			const store = getProjectStore();
			if (await store.findBySlug(body.slug)) {
				throw new AdminError(409, 'slug already exists');
			}
			// Allocated here so the audit entry can name the project that is about to exist.
			const projectId = nanoid();
			await recordAdminAudit(ctx, 'project.create', projectId, {
				ownerGroupId
			});
			// Every accepted key must be forwarded explicitly: the store takes more than this handler
			// passes, so a schema addition alone would accept a value and silently discard it.
			const project = await store.create({
				_id: projectId,
				name: body.name,
				slug: body.slug,
				type: 'regular',
				ownerGroupId,
				corsOrigins: validateCorsOrigins(body.corsOrigins) ?? []
			});
			set.status = 201;
			return project;
		},
		{ body: CreateProjectBody }
	)
	.get('/admin/api/projects/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		return loadProject(ctx, params.id);
	})
	.patch(
		'/admin/api/projects/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const project = await loadProject(ctx, params.id);
			if (project.type === 'admin')
				throw new AdminError(403, 'cannot modify admin project');
			const corsOrigins = validateCorsOrigins(body.corsOrigins);
			// After origin validation: an entry for a request that was about to be refused as malformed
			// would describe a change nobody attempted.
			await recordAdminAudit(ctx, 'project.update', params.id, {
				attributes: Object.keys(body),
				ownerGroupId: project.ownerGroupId
			});
			return getProjectStore().update(params.id, {
				...body,
				...(corsOrigins === undefined ? {} : { corsOrigins })
			});
		},
		{ body: UpdateProjectBody }
	)
	.delete(
		'/admin/api/projects/:id',
		async ({ admin, params, query }) => {
			const ctx = assertAuth(admin);
			const project = await loadProject(ctx, params.id);
			if (project.type === 'admin')
				throw new AdminError(403, 'cannot delete admin project');
			/*
			 * Ownership, not role: a group deletes what it owns. What protects the contents is the
			 * election below, not who may ask — widening who may ask did not widen what may be destroyed.
			 */
			/*
			 * Only ids that still *resolve* count. An id left behind after its client vanished must never
			 * make a project permanently undeletable, and must never be offered to an administrator as
			 * something they are consenting to destroy.
			 *
			 * An assigned bucket is deliberately absent from all of this: buckets are shared, they hold
			 * people who have no relationship with any one project, and no election reaches one.
			 */
			const held = (
				await Promise.all(
					project.clientIds.map(async (clientId) =>
						(await Client.tryFind(clientId)) ? clientId : null
					)
				)
			).filter((clientId): clientId is string => clientId !== null);

			const consented = normalizeConsentedClients(query.client);
			if (consented !== null && query.cascade === undefined) {
				throw new AdminError(
					400,
					'client requires cascade=clients: consenting to destroy a set nobody elected to destroy is not a request that means anything'
				);
			}

			if (held.length > 0) {
				/*
				 * Two different refusals, and the difference is what the operator does next. Without an
				 * election they have not decided yet; with one that no longer matches, they decided about
				 * a list that has since changed and have to look again.
				 */
				if (query.cascade === undefined) {
					throw new AdminError(409, 'project still holds clients', {
						blockers: [{ kind: 'client', count: held.length, ids: held }]
					});
				}
				if (!sameSet(held, consented ?? [])) {
					throw new AdminError(
						409,
						'the project clients changed since you reviewed them',
						{ blockers: [{ kind: 'client', count: held.length, ids: held }] }
					);
				}
			}

			/*
			 * Declared protected resources go without being elected, unlike clients — and the difference
			 * is what each thing is. A client is an entity in its own right, with its own credentials and
			 * its own integrations, so destroying one is a decision. A resource declaration is a property
			 * of the project: leaving one behind would strand an audience whose owning project no longer
			 * exists, reachable by nobody and deletable through no route.
			 */
			const declared = await getProtectedResourceStore().listByProject(
				params.id
			);

			/*
			 * One entry, carrying counts — not one per client and one per declaration, as this wrote
			 * until 051. The old shape argued that a bare number would not say which audiences stopped
			 * being served, and that held while a project could only be deleted empty. It does not
			 * survive the cascade: a deletion is all-or-nothing over what the project held, so the
			 * project's identity already determines which clients and which declarations those were, and
			 * a row per destroyed item would let one bucket-sized deletion bury everything else an
			 * operator needs to investigate.
			 *
			 * Written after the guards and before the destruction, by the trail's own contract: an entry
			 * attests that an authorized actor reached the point of applying this change, which is why
			 * recording what is about to go is correct rather than optimistic.
			 */
			const cascade = {
				...(held.length > 0 ? { clients: held.length } : {}),
				...(declared.length > 0 ? { resources: declared.length } : {})
			};
			await recordAdminAudit(ctx, 'project.delete', params.id, {
				ownerGroupId: project.ownerGroupId,
				...(Object.keys(cascade).length > 0 ? { cascade } : {})
			});

			/*
			 * Each client destroyed exactly as deleting it on its own destroys it. The shallow version —
			 * drop the record, leave what it issued — is the failure that looks correct from the console:
			 * the client disappears from the list while a registration access token it holds may carry no
			 * expiry at all. A failed sweep is reported, never rolled back, because the principal is
			 * already gone by then and closing the door first is the point.
			 */
			const failedAreas: string[] = [];
			for (const clientId of held) {
				await deleteClientRecord(clientId);
				const swept = await cascadeForClient(clientId);
				failedAreas.push(...swept.failedAreas);
			}

			await getProtectedResourceStore().destroyByProject(params.id);
			await getProjectStore().destroy(params.id);

			if (failedAreas.length > 0) {
				throw new AdminError(
					500,
					`project deleted, but records of its clients survive in: ${[...new Set(failedAreas)].join(', ')}`,
					{ failedAreas: [...new Set(failedAreas)] }
				);
			}
			return {
				ok: true,
				clientsDestroyed: held.length,
				resourcesRemoved: declared.length
			};
		},
		{ query: DeleteProjectQuery }
	)
	.put(
		'/admin/api/projects/:id/bucket',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const project = await loadProject(ctx, params.id);
			const bucket = await getBucketStore().find(body.bucketId);
			if (!bucket) throw new AdminError(404, 'bucket not found');
			/*
			 * Refused before ownership is considered, because ownership does not actually cover it — it
			 * only looks as though it does. The administrators' own bucket sits in the System group, and a
			 * super administrator whose active scope is empty creates projects into that same group
			 * (`assertActiveGroup`), so for those projects the rule below compares `unassigned` with
			 * `unassigned` and passes. Without this an ordinary project could be backed by the very
			 * accounts that administer the instance. Same refusal as `assertNotReserved` in
			 * `lib/admin/buckets/access.ts`, which this route does not go through.
			 */
			if (bucket._id === ADMIN_BUCKET_ID) {
				throw new AdminError(
					403,
					"this operation is not available for the administrators' bucket"
				);
			}
			assertBucketAccess(ctx, bucket);
			/*
			 * A project and the bucket backing it must belong to the same group. Both access checks above
			 * can pass for an administrator who belongs to two groups — one owning the project, the other
			 * the bucket — and letting that through would build a tenant whose end-users live in somebody
			 * else's scope, reachable by people with no access to the project at all.
			 *
			 * It is not a way to reach the default bucket, and does not need to be. A project whose bucket
			 * is unset already signs its users in from `redfox`, because `resolveBucketForRequest` falls
			 * through on an empty `bucketId` to exactly that default. Leaving the bucket unset is the
			 * supported way to use it; admitting the System group here would relax a tenant boundary to buy
			 * nothing.
			 */
			if (bucket.ownerGroupId !== project.ownerGroupId) {
				throw new AdminError(
					409,
					'project and bucket must belong to the same group'
				);
			}
			const move = await planMove(
				ctx,
				project._id,
				await namespaceOfProject(project),
				namespaceOf(bucket)
			);
			// The project is the entity being changed; which bucket it was pointed at is a submitted
			// field, so it is recorded as a field name rather than a value.
			await recordAdminAudit(ctx, 'project.bucket.assign', params.id, {
				attributes: Object.keys(body),
				ownerGroupId: project.ownerGroupId
			});
			await applyMove(project._id, move);
			const bound = await getProjectStore().update(params.id, {
				bucketId: body.bucketId
			});
			/*
			 * Checked again after the write, because a move of the bucket to another group can commit between
			 * the check above and the write: it carries the projects using the bucket at that moment, and this
			 * one was not yet among them. Whichever of the two writes comes second sees the other, so reading
			 * the bucket now is enough to keep a project from ending up in a different group from its bucket.
			 */
			const settled = await getBucketStore().find(bucket._id);
			if (settled?.ownerGroupId !== project.ownerGroupId) {
				await getProjectStore().update(params.id, {
					bucketId: project.bucketId
				});
				// Back where they were: no plan check, since this restores a namespace they held a moment ago.
				await applyMove(project._id, {
					from: move.to,
					to: move.from,
					count: move.count
				});
				throw new AdminError(
					409,
					'project and bucket must belong to the same group'
				);
			}
			return bound;
		},
		{ body: SetBucketBody }
	)
	/*
	 * Its own route rather than a null the PUT accepts, because the audit trail records field *names*
	 * and never values: one action would have written `project.bucket.assign` for a removal, and the
	 * trail could not tell an operator which of the two had happened.
	 *
	 * Assigning was one-way until this existed — the body took a bucket id and had no value meaning
	 * "none" — so a project pointed at the wrong bucket stayed pointed at it. Clearing returns it to the
	 * default bucket, which is what `resolveBucketForRequest` falls through to on an empty `bucketId`.
	 */
	.delete('/admin/api/projects/:id/bucket', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const project = await loadProject(ctx, params.id);
		/*
		 * Project access only, deliberately. The entity changed is the project, and dropping a pointer
		 * needs no authority over what it pointed at — a caller who has lost access to the bucket is
		 * precisely somebody who needs to clear it. Its declarations are another matter: clearing moves
		 * them into the shared root namespace, which only a super administrator writes.
		 */
		const move = await planMove(
			ctx,
			project._id,
			await namespaceOfProject(project),
			ROOT_NAMESPACE
		);
		await recordAdminAudit(ctx, 'project.bucket.clear', params.id, {
			ownerGroupId: project.ownerGroupId
		});
		await applyMove(project._id, move);
		return getProjectStore().update(params.id, { bucketId: null });
	})
	/*
	 * Moving a project with no bucket to another administrator group (specs/075). A project that uses a
	 * bucket moves with it, through the bucket's route: a project and the bucket it signs into must share a
	 * group, so neither moves alone.
	 *
	 * The same rules as the bucket's move, from the same module: an owner of the group it leaves, a member
	 * of the one it joins, and never another administrator's personal group.
	 */
	.put(
		'/admin/api/projects/:id/owner',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const project = await loadProject(ctx, params.id);
			/*
			 * Refused for everyone: `loadProject` admits a super administrator to the console's own project,
			 * which belongs to no tenant and must stay in the System group with the bucket it signs into.
			 */
			if (project.type === 'admin') {
				throw new AdminError(403, 'no access to this project');
			}
			if (project.bucketId !== null) {
				throw new AdminError(
					409,
					'a project using a bucket moves with its bucket'
				);
			}
			const destination = await loadDestination(ctx, body.groupId);
			const from = sourceGroupOf([project.ownerGroupId], destination._id);
			assertGroupOwner(ctx, from);

			if (body.confirm !== true) {
				set.status = 409;
				return {
					confirmationRequired: true as const,
					from: await describeGroup(from),
					to: await describeGroup(destination._id),
					project: { id: project._id, name: project.name },
					consequence:
						'the project and its clients will be administered by the members of the destination group, and no longer by members of the source group only; its clients keep working unchanged'
				};
			}

			await recordAdminAudit(ctx, 'project.owner.change', project._id, {
				ownerGroupId: destination._id,
				formerOwnerGroupId: from,
				attributes: ['ownerGroupId']
			});
			const result = await getContainerOwnershipStore().moveProject(
				project._id,
				from,
				destination._id
			);
			if (result.status === 'conflict') {
				throw new AdminError(
					409,
					'the project changed while it was being moved; reload and try again'
				);
			}
			return { project: { id: project._id, ownerGroupId: destination._id } };
		},
		{ body: MoveProjectOwnerBody }
	);
