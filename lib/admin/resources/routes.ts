import { Elysia } from 'elysia';

import { getProtectedResourceStore } from '../../adapters/index.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { loadProject } from '../projects/access.js';
import { recordAdminAudit } from '../audit/record.js';
import { canonicalizeResourceIdentifier } from '../../resources/canonical.js';
import { validateScopes, scopeFailureMessage } from '../../resources/scopes.js';
import { isMcpResource } from '../../mcp/resource_server.js';
import { CreateResourceBody, UpdateResourceBody } from './schema.js';

/*
 * Declared protected resources: the audiences this server will mint tokens for, owned by a project.
 *
 * Authorization is the project's, not a role's — `loadProject` resolves the project and refuses an
 * outsider identically whether it exists or not. Nothing here gates on `super_admin`: declaring a
 * resource is ordinary work for the administrator who owns the project, and the instance-wide
 * surfaces (settings, keys, the administrative permission list) are the ones that stay reserved.
 */

/*
 * Canonicalizes a submitted identifier or refuses the request.
 *
 * The reserved check sits here rather than only in the store because the built-in arm of
 * `getResourceServerInfo` claims this server's own MCP audience *before* the store is consulted — so a
 * declaration naming it could never take effect. Refusing at declaration time turns a silently inert
 * record into a stated conflict, which is the difference between an operator learning the rule and an
 * operator filing a bug.
 */
function canonicalIdentifier(input: string): string {
	const result = canonicalizeResourceIdentifier(input);
	if (!result.ok) {
		throw new AdminError(
			400,
			result.reason === 'fragment'
				? 'a resource identifier must not carry a fragment'
				: 'a resource identifier must be an absolute URI'
		);
	}
	if (isMcpResource(result.identifier)) {
		throw new AdminError(
			409,
			'that identifier names an audience this server serves itself'
		);
	}
	return result.identifier;
}

function acceptedScopes(scopes: string[]): string[] {
	const result = validateScopes(scopes);
	if (!result.ok) {
		throw new AdminError(400, scopeFailureMessage(result.reason, result.value));
	}
	return result.scopes;
}

/*
 * Loads a declared resource, and refuses one that belongs to a different project than the path names.
 *
 * The second half matters: identifiers are instance-unique, so `/projects/A/resources/<B's audience>`
 * would otherwise read — and amend — another tenant's declaration through a project the caller does
 * legitimately own. A 404 rather than a 403, because from this project's point of view the resource
 * genuinely is not there.
 */
async function loadResource(projectId: string, identifier: string) {
	const resource = await getProtectedResourceStore().find(identifier);
	if (!resource || resource.projectId !== projectId) {
		throw new AdminError(404, 'resource not declared in this project');
	}
	return resource;
}

export const resourceRoutes = new Elysia({ name: 'admin-resources' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/projects/:id/resources', async ({ admin, params }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		await loadProject(ctx, params.id);
		return getProtectedResourceStore().listByProject(params.id);
	})
	.post(
		'/admin/api/projects/:id/resources',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadProject(ctx, params.id);

			const identifier = canonicalIdentifier(body.identifier);
			const scopes = acceptedScopes(body.scopes);

			/*
			 * Checked before the audit write so a refused declaration leaves no entry describing a change
			 * nobody made — and enforced again by the store, which is where it actually holds: the
			 * identifier is the primary key, so a concurrent duplicate is refused by the datastore rather
			 * than by this read.
			 */
			if (await getProtectedResourceStore().find(identifier)) {
				throw new AdminError(409, 'that identifier is already declared');
			}

			await recordAdminAudit(ctx, 'resource.create', identifier, {
				ownerGroupId: project.ownerGroupId
			});

			try {
				const resource = await getProtectedResourceStore().create({
					_id: identifier,
					projectId: params.id,
					name: body.name,
					scopes,
					tokenFormat: body.tokenFormat,
					accessTokenTTL: body.accessTokenTTL,
					trailingSlashSignificant: body.trailingSlashSignificant
				});
				set.status = 201;
				return resource;
			} catch {
				/*
				 * The primary key refused it between the read above and this write. A conflict rather than a
				 * 500: the caller's request was well-formed, and the answer is the same one the read would
				 * have given a moment earlier.
				 */
				throw new AdminError(409, 'that identifier is already declared');
			}
		},
		{ body: CreateResourceBody }
	)
	.get(
		'/admin/api/projects/:id/resources/:resourceId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			await loadProject(ctx, params.id);
			return loadResource(params.id, canonicalIdentifier(params.resourceId));
		}
	)
	.patch(
		'/admin/api/projects/:id/resources/:resourceId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadProject(ctx, params.id);
			const identifier = canonicalIdentifier(params.resourceId);
			await loadResource(params.id, identifier);

			const scopes =
				body.scopes === undefined ? undefined : acceptedScopes(body.scopes);

			// After validation: an entry for a request about to be refused as malformed would describe a
			// change nobody attempted.
			await recordAdminAudit(ctx, 'resource.update', identifier, {
				attributes: Object.keys(body),
				ownerGroupId: project.ownerGroupId
			});

			return getProtectedResourceStore().update(identifier, {
				...body,
				...(scopes === undefined ? {} : { scopes })
			});
		},
		{ body: UpdateResourceBody }
	)
	.delete(
		'/admin/api/projects/:id/resources/:resourceId',
		async ({ admin, params, set }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadProject(ctx, params.id);
			const identifier = canonicalIdentifier(params.resourceId);
			await loadResource(params.id, identifier);

			await recordAdminAudit(ctx, 'resource.delete', identifier, {
				ownerGroupId: project.ownerGroupId
			});

			await getProtectedResourceStore().destroy(identifier);
			set.status = 204;
			return null;
		}
	);
