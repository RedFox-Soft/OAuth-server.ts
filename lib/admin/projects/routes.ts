import { Elysia } from 'elysia';
import {
	getProjectStore,
	getBucketStore,
	getProtectedResourceStore
} from '../../adapters/index.js';
import type { Project } from '../../adapters/types.js';
import {
	assertAuth,
	assertActiveGroup,
	assertProjectAccess,
	assertBucketAccess,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import {
	CreateProjectBody,
	UpdateProjectBody,
	SetBucketBody
} from './schema.js';
import {
	InvalidOriginError,
	normalizeOrigins
} from '../../helpers/cors_origin.js';
import { loadProject } from './access.js';
import { recordAdminAudit } from '../audit/record.js';
import { Client } from '../../models/client.js';
import nanoid from '../../helpers/nanoid.js';

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

export const projectRoutes = new Elysia({ name: 'admin-projects' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/projects', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const store = getProjectStore();
		/*
		 * Scope-filtered, not role-gated. A super administrator sees the instance; everyone else sees the
		 * group their console is pointed at — not every group they belong to, because the console has one
		 * active scope and a list mixing two tenants is the thing scope switching exists to prevent.
		 */
		const all = ctx.roles.includes('super_admin')
			? (await store.list()).filter((p) => p.type === 'regular')
			: (await store.listByGroup(ctx.activeGroupId)).filter(
					(p) => p.type === 'regular'
				);
		return all;
	})
	.post(
		'/admin/api/projects',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
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
		const ctx = assertAuth(admin as AdminContext | null);
		return loadProject(ctx, params.id);
	})
	.patch(
		'/admin/api/projects/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
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
	.delete('/admin/api/projects/:id', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		const project = await loadProject(ctx, params.id);
		if (project.type === 'admin')
			throw new AdminError(403, 'cannot delete admin project');
		/*
		 * Ownership, not role: a group deletes what it owns. The client-blocker refusal below is what
		 * actually protects the contents, and it is unchanged — widening who may ask did not widen what
		 * may be destroyed.
		 */
		/*
		 * A project is guarded rather than cascaded: its clients are things the operator can see and name,
		 * so refusing says exactly what is in the way and leaves one audit entry per client actually
		 * destroyed. Only ids that still *resolve* block — an id left behind after its client vanished
		 * must never make a project permanently undeletable — and a refused request prunes nothing,
		 * because a conflict changes nothing at all.
		 *
		 * An assigned bucket is deliberately not a blocker: buckets are shared and outlive projects.
		 */
		const held = (
			await Promise.all(
				project.clientIds.map(async (clientId) =>
					(await Client.tryFind(clientId)) ? clientId : null
				)
			)
		).filter((clientId): clientId is string => clientId !== null);
		if (held.length > 0) {
			throw new AdminError(409, 'project still holds clients', {
				blockers: [{ kind: 'client', count: held.length, ids: held }]
			});
		}
		/*
		 * Declared protected resources cascade rather than block, which is the opposite of the rule for
		 * clients above — and the difference is what each thing is. A client is an entity an operator
		 * can see and name, so refusing tells them exactly what is in the way. A resource declaration is
		 * a property of the project: leaving one behind would strand an audience whose owning project no
		 * longer exists, reachable by nobody and deletable through no route.
		 *
		 * One audit entry per declaration actually withdrawn, the same shape the client rule above
		 * describes. Not a count on the project's own entry: an audit entry carries field *names* and
		 * never values, deliberately, so that no secret can reach the trail — and a bare number would in
		 * any case not say which audiences stopped being served. Named entries make the trail
		 * reconstructible after the declarations themselves are gone.
		 */
		const declared = await getProtectedResourceStore().listByProject(params.id);

		// After the guard: an entry for a request the 409 refused would describe a deletion never attempted.
		for (const resource of declared) {
			await recordAdminAudit(ctx, 'resource.delete', resource._id, {
				ownerGroupId: project.ownerGroupId
			});
		}
		await recordAdminAudit(ctx, 'project.delete', params.id, {
			ownerGroupId: project.ownerGroupId
		});
		await getProtectedResourceStore().destroyByProject(params.id);
		await getProjectStore().destroy(params.id);
		return { ok: true, resourcesRemoved: declared.length };
	})
	.put(
		'/admin/api/projects/:id/bucket',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadProject(ctx, params.id);
			const bucket = await getBucketStore().find(body.bucketId);
			if (!bucket) throw new AdminError(404, 'bucket not found');
			assertBucketAccess(ctx, bucket);
			/*
			 * A project and the bucket backing it must belong to the same group. Both access checks above
			 * can pass for an administrator who belongs to two groups — one owning the project, the other
			 * the bucket — and letting that through would build a tenant whose end-users live in somebody
			 * else's scope, reachable by people with no access to the project at all.
			 */
			if (bucket.ownerGroupId !== project.ownerGroupId) {
				throw new AdminError(
					409,
					'project and bucket must belong to the same group'
				);
			}
			// The project is the entity being changed; which bucket it was pointed at is a submitted
			// field, so it is recorded as a field name rather than a value.
			await recordAdminAudit(ctx, 'project.bucket.assign', params.id, {
				attributes: Object.keys(body),
				ownerGroupId: project.ownerGroupId
			});
			return getProjectStore().update(params.id, { bucketId: body.bucketId });
		},
		{ body: SetBucketBody }
	);
