import { Elysia, t } from 'elysia';
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
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import {
	managesProject,
	mayMoveProject,
	projectCan,
	type ProjectCan
} from '../auth/can.js';
import type { Project, UserBucket } from '../../adapters/types.js';
import {
	CreateProjectBody,
	UpdateProjectBody,
	SetBucketBody,
	ClearBucketBody,
	DeleteProjectQuery,
	MoveProjectOwnerBody
} from './schema.js';
import { deleteClientRecord, getClientView } from '../clients/service.js';
import { cascadeForClient } from '../../helpers/cascade.js';
import {
	InvalidOriginError,
	normalizeOrigins
} from '../../helpers/cors_origin.js';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from '../consts.js';
import { isScheduledForDeletion } from '../../consts/bucket_deletion.js';
import {
	describeGroup,
	loadDestination,
	sourceGroupOf
} from '../ownership/destination.js';
import { loadProject } from './access.js';
import { recordAdminAudit } from '../audit/record.js';
import { Client } from '../../models/client.js';
import nanoid from '../../helpers/nanoid.js';
import { namespaceOf, ROOT_NAMESPACE } from '../../resources/namespace.js';
import {
	applyMove,
	DeclarationsConflict,
	planMove,
	previewMove
} from '../resources/move.js';
import {
	addressOf,
	DEFAULT_REQUEST_BUCKET,
	issuerFor
} from '../../configs/issuer.js';

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
			throw new AdminError(400, err.message, { field: 'corsOrigins' });
		}
		throw err;
	}
}

/*
 * A bucket scheduled for deletion takes no new project (specs/090 FR-011): it answers nobody, and a project
 * pointing at it would also block its deletion from completing. After the access check, so only a caller who
 * may reach the bucket learns it is scheduled.
 */
function assertNotScheduled(bucket: UserBucket): void {
	if (isScheduledForDeletion(bucket)) {
		throw new AdminError(409, 'That bucket is scheduled for deletion.');
	}
}

/*
 * The bucket a new project is created with (specs/087), refused by the rules an assignment is: it exists,
 * it is not the administrators' bucket, the caller reaches it, and it is in the group the project is
 * created in. No preview, unlike an assignment: a new project has no applications or declarations whose
 * issuer could change.
 *
 * The default bucket is refused by name rather than admitted: leaving `bucketId` out is how a project uses
 * it, and it belongs to the System group, so admitting it would succeed only for a super administrator
 * creating there — two spellings of one state, one of them reachable by almost nobody.
 */
async function bucketForNewProject(
	ctx: AdminContext,
	bucketId: string,
	ownerGroupId: string
): Promise<UserBucket> {
	if (bucketId === DEFAULT_BUCKET_ID) {
		throw new AdminError(422, 'leave bucketId out to use the default bucket', {
			field: 'bucketId'
		});
	}
	const bucket = await getBucketStore().find(bucketId);
	/* Answered as a bucket the caller cannot reach, unless they reach every bucket: no existence oracle. */
	if (!bucket) {
		throw ctx.superAdmin
			? new AdminError(404, 'bucket not found')
			: new AdminError(403, 'no access to this bucket');
	}
	if (bucket._id === ADMIN_BUCKET_ID) {
		throw new AdminError(
			403,
			"this operation is not available for the administrators' bucket"
		);
	}
	assertBucketAccess(ctx, bucket);
	assertNotScheduled(bucket);
	if (bucket.ownerGroupId !== ownerGroupId) {
		throw new AdminError(
			409,
			'project and bucket must belong to the same group'
		);
	}
	return bucket;
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

/* As stored: a project document written before `clientIds` existed has none. */
function clientIdsOf(project: {
	clientIds?: readonly string[];
}): readonly string[] {
	return project.clientIds ?? [];
}

type AddressForm = ReturnType<typeof addressOf>['kind'];

/*
 * The project's bucket as a row names it (specs/085), so a list says which bucket each project signs in
 * through without the caller reading the buckets — which a super administrator in another scope, or an
 * agent, would otherwise have to join by id. Null for the default bucket, and for a bucket record that is
 * gone, which the namespace reads the same way: served at the root.
 */
function bucketOfRow(
	bucket: UserBucket | undefined
): { id: string; name: string; addressForm: AddressForm } | null {
	if (!bucket) return null;
	return {
		id: bucket._id,
		name: bucket.name,
		addressForm: addressOf(bucket).kind
	};
}

/*
 * The caller's rights on each project, and the state that would refuse one they hold. The namespace a
 * project declares into is read from its bucket, so the buckets are read once per distinct id rather than
 * once per row.
 */
async function withRights<T extends Project>(
	ctx: AdminContext,
	projects: readonly T[]
): Promise<
	(T & {
		can: ProjectCan;
		blockers: { hasBucket: boolean };
		bucket: ReturnType<typeof bucketOfRow>;
		clientCount: number;
	})[]
> {
	const buckets = new Map<string, UserBucket>();
	for (const id of new Set(projects.map((project) => project.bucketId))) {
		const bucket = id ? await getBucketStore().find(id) : null;
		if (id && bucket) buckets.set(id, bucket);
	}
	return projects.map((project) => {
		const bucket = project.bucketId ? buckets.get(project.bucketId) : undefined;
		return {
			...project,
			can: projectCan(ctx, {
				...project,
				namespace: bucket ? namespaceOf(bucket) : ROOT_NAMESPACE
			}),
			/* As the move route reads it: a project using a bucket moves only with it. */
			blockers: { hasBucket: project.bucketId !== null },
			bucket: bucketOfRow(bucket),
			clientCount: clientIdsOf(project).length
		};
	});
}

interface BucketSide {
	bucketId: string | null;
	name: string;
	issuer: string | null;
}

/*
 * One end of a bucket change, as the preview names it. A project with no bucket signs in at the default
 * bucket, so "none" is named as that and given the root issuer; a bucket with no address of its own has no
 * issuer a client could be configured with, so null rather than the id-derived fallback.
 */
function sideOf(
	bucketId: string | null,
	bucket: UserBucket | null
): BucketSide {
	if (bucketId === null) {
		return {
			bucketId: null,
			name: 'Default bucket',
			issuer: issuerFor(DEFAULT_REQUEST_BUCKET)
		};
	}
	if (!bucket) return { bucketId, name: bucketId, issuer: null };
	return {
		bucketId,
		name: bucket.name,
		issuer: addressOf(bucket).kind === 'unaddressed' ? null : issuerFor(bucket)
	};
}

interface BucketChangeCounts {
	applications: number;
	resources: number;
}

interface BucketChangePreview {
	from: BucketSide;
	to: BucketSide;
	applications: { clientId: string; name: string | null }[];
	resources: { identifier: string; name: string }[];
	conflicts: string[];
	rootRefused: boolean;
	blocked: boolean;
	consequence: string;
	expect: BucketChangeCounts;
}

/*
 * Everything a change of a project's bucket reaches, named before the change (specs/085), as an address
 * change names what it reaches (`lib/admin/buckets/routes.ts`): each application by name, because the
 * people signed in through it are who the operator has to warn; each declaration that moves namespace; and
 * what would block it — identifiers already taken where they would go, or the shared root this caller may
 * not write.
 *
 * Token behaviour is described, not changed: a token already issued names the issuer that issued it and
 * keeps verifying until it expires.
 */
async function bucketChangePreview(
	ctx: AdminContext,
	project: Project,
	from: { bucketId: string | null; bucket: UserBucket | null },
	to: { bucketId: string | null; bucket: UserBucket | null }
): Promise<BucketChangePreview> {
	const applications: BucketChangePreview['applications'] = [];
	for (const clientId of clientIdsOf(project)) {
		const view = await getClientView(clientId);
		applications.push({ clientId, name: view?.clientName ?? null });
	}
	/* By name, the unnamed last, then by id, so two reads of the same project list it the same way. */
	applications.sort(
		(a, b) =>
			Number(a.name === null) - Number(b.name === null) ||
			(a.name ?? '').localeCompare(b.name ?? '') ||
			a.clientId.localeCompare(b.clientId)
	);
	const moves = await previewMove(
		ctx,
		project._id,
		from.bucket ? namespaceOf(from.bucket) : ROOT_NAMESPACE,
		to.bucket ? namespaceOf(to.bucket) : ROOT_NAMESPACE
	);
	const resources = moves.moving.map((resource) => ({
		identifier: resource.identifier,
		name: resource.name
	}));
	return {
		from: sideOf(from.bucketId, from.bucket),
		to: sideOf(to.bucketId, to.bucket),
		applications,
		resources,
		conflicts: [...moves.conflicts],
		rootRefused: moves.rootRefused,
		blocked: moves.conflicts.length > 0 || moves.rootRefused,
		consequence:
			"the issuer of every application listed changes: people signed in through them must sign in again in the new bucket, and their accounts do not move with the project; tokens already issued keep working until they expire; the declared resources listed move to the new bucket's namespace",
		expect: {
			applications: applications.length,
			resources: resources.length
		}
	};
}

/*
 * The answer to an unconfirmed change, or to a confirmation of counts that are no longer true: the preview,
 * and nothing written — no audit entry, because nothing was applied. Null when the change may proceed.
 *
 * The consent is to the counts shown. An application or a declaration that arrived while the preview was
 * open is not covered by it, so the change is refused with the fresh preview.
 */
function unconfirmed(
	body: { confirm?: true; expect?: BucketChangeCounts } | null | undefined,
	preview: BucketChangePreview
) {
	if (body?.confirm !== true) {
		return { confirmationRequired: true as const, ...preview };
	}
	const expect = body.expect;
	if (
		expect === undefined ||
		expect.applications !== preview.expect.applications ||
		expect.resources !== preview.expect.resources
	) {
		return {
			error: 'admin_error' as const,
			message:
				expect === undefined
					? 'confirm with the counts of the preview you reviewed (expect)'
					: 'what this bucket change reaches changed since you reviewed it',
			...preview,
			confirmationRequired: true as const
		};
	}
	return null;
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
		return withRights(ctx, all);
	})
	.post(
		'/admin/api/projects',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin);
			/*
			 * No role gate. Creating a project is what a project administrator signs in to do, and the
			 * authority that matters is membership of the group it will belong to: the active group, or a
			 * group the caller names (specs/087), held to the rules a move into it is held to — so naming a
			 * group admits nothing a move would refuse.
			 */
			const ownerGroupId =
				body.groupId === undefined
					? assertActiveGroup(ctx)
					: (await loadDestination(ctx, body.groupId))._id;
			const bucket =
				body.bucketId === undefined
					? null
					: await bucketForNewProject(ctx, body.bucketId, ownerGroupId);
			const store = getProjectStore();
			if (await store.findBySlug(body.slug)) {
				throw new AdminError(409, 'slug already exists', { field: 'slug' });
			}
			const corsOrigins = validateCorsOrigins(body.corsOrigins) ?? [];
			// Allocated here so the audit entry can name the project that is about to exist.
			const projectId = nanoid();
			/*
			 * With a bucket, the entry carries it as an assignment's does, so the creation is in that bucket's
			 * trail too.
			 */
			await recordAdminAudit(ctx, 'project.create', projectId, {
				attributes: Object.keys(body),
				ownerGroupId,
				...(bucket ? { bucketId: bucket._id } : {})
			});
			// Every accepted key must be forwarded explicitly: the store takes more than this handler
			// passes, so a schema addition alone would accept a value and silently discard it.
			const project = await store.create({
				_id: projectId,
				name: body.name,
				slug: body.slug,
				type: 'regular',
				ownerGroupId,
				corsOrigins,
				...(bucket ? { bucketId: bucket._id } : {})
			});
			/*
			 * Checked again after the write, as an assignment is: a move of the bucket to another group can
			 * commit in between, carrying the projects that used it then — not this one. A project with no
			 * clients yet is simply not kept, so nothing is left in a group other than its bucket's.
			 */
			if (bucket) {
				const settled = await getBucketStore().find(bucket._id);
				if (settled?.ownerGroupId !== ownerGroupId) {
					await store.destroy(projectId);
					throw new AdminError(
						409,
						'project and bucket must belong to the same group'
					);
				}
			}
			set.status = 201;
			return project;
		},
		{ body: CreateProjectBody }
	)
	.get('/admin/api/projects/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin);
		const [presented] = await withRights(ctx, [
			await loadProject(ctx, params.id)
		]);
		return presented;
	})
	.patch(
		'/admin/api/projects/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const project = await loadProject(ctx, params.id);
			if (!managesProject(ctx, project))
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
			if (!managesProject(ctx, project))
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
		async ({ admin, params, body, set }) => {
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
			assertNotScheduled(bucket);
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
			/*
			 * After every refusal above, so a caller without access learns nothing from a preview, and a preview
			 * is never offered for a change that would be refused anyway; before the audit entry, so nothing is
			 * recorded for a change that was only described.
			 */
			const former =
				project.bucketId === null
					? null
					: await getBucketStore().find(project.bucketId);
			const preview = await bucketChangePreview(
				ctx,
				project,
				{ bucketId: project.bucketId, bucket: former },
				{ bucketId: bucket._id, bucket }
			);
			const pending = unconfirmed(body, preview);
			if (pending) {
				set.status = 409;
				return pending;
			}
			/* The confirm-time check: a change the preview showed as blocked is refused here, as it always was. */
			const move = await planMove(
				ctx,
				project._id,
				former ? namespaceOf(former) : ROOT_NAMESPACE,
				namespaceOf(bucket)
			);
			/*
			 * Both buckets name the entry, so it is in the history of the one the project joined and of the one
			 * it left; `attributes` stays the field name the change set.
			 */
			await recordAdminAudit(ctx, 'project.bucket.assign', params.id, {
				attributes: ['bucketId'],
				ownerGroupId: project.ownerGroupId,
				bucketId: bucket._id,
				...(project.bucketId === null
					? {}
					: { formerBucketId: project.bucketId })
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
	 * Its own route rather than a null the PUT accepts, because the action is what tells a reader of the
	 * trail which change happened: one action would have written `project.bucket.assign` for a removal,
	 * and the trail could not tell an operator which of the two had happened.
	 *
	 * Assigning was one-way until this existed — the body took a bucket id and had no value meaning
	 * "none" — so a project pointed at the wrong bucket stayed pointed at it. Clearing returns it to the
	 * default bucket, which is what `resolveBucketForRequest` falls through to on an empty `bucketId`.
	 */
	.delete(
		'/admin/api/projects/:id/bucket',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const project = await loadProject(ctx, params.id);
			/*
			 * Project access only, deliberately. The entity changed is the project, and dropping a pointer
			 * needs no authority over what it pointed at — a caller who has lost access to the bucket is
			 * precisely somebody who needs to clear it. Its declarations are another matter: clearing moves
			 * them into the shared root namespace, which only a super administrator writes — the preview says
			 * so as `rootRefused`, and the confirmed change is refused for it.
			 */
			const former =
				project.bucketId === null
					? null
					: await getBucketStore().find(project.bucketId);
			const preview = await bucketChangePreview(
				ctx,
				project,
				{ bucketId: project.bucketId, bucket: former },
				{ bucketId: null, bucket: null }
			);
			const pending = unconfirmed(body, preview);
			if (pending) {
				set.status = 409;
				return pending;
			}
			const move = await planMove(
				ctx,
				project._id,
				former ? namespaceOf(former) : ROOT_NAMESPACE,
				ROOT_NAMESPACE
			);
			/* In the history of the bucket the project left. */
			await recordAdminAudit(ctx, 'project.bucket.clear', params.id, {
				ownerGroupId: project.ownerGroupId,
				...(project.bucketId === null
					? {}
					: { formerBucketId: project.bucketId })
			});
			await applyMove(project._id, move);
			return getProjectStore().update(params.id, { bucketId: null });
		},
		{ body: t.Optional(ClearBucketBody) }
	)
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
			 * Refused for everyone on the console's own project: `loadProject` admits a super administrator
			 * to it, but it belongs to no tenant and must stay in the System group with the bucket it signs
			 * into. On any other, an owner's act — and decided before the state below, so a member who may
			 * not move a project is told that rather than how it is attached.
			 */
			if (!mayMoveProject(ctx, project)) {
				throw new AdminError(
					403,
					project.type === 'admin'
						? 'no access to this project'
						: 'group owner required'
				);
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
