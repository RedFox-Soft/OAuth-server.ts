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
import { SCIM_BASE_PATH } from '../../consts/scim.js';
import { CreateResourceBody, UpdateResourceBody } from './schema.js';
import {
	namespaceOfProject,
	ROOT_NAMESPACE
} from '../../resources/namespace.js';
import { findDeclaredResource } from '../../resources/registry.js';
import { checkVouching } from '../../resources/vouching.js';
import { issuerFor } from '../../configs/issuer.js';
import { issuingBucket } from '../auth/bucketAddress.js';
import { ISSUER } from '../../configs/env.js';
import { isUniqueValueTaken } from '../../adapters/conflicts.js';
import { ROOT_DECLARATION_REFUSAL } from './refusals.js';

/*
 * Declared protected resources: the audiences this server will mint tokens for, owned by a project.
 *
 * Authorization is the project's, not a role's — `loadProject` resolves the project and refuses an
 * outsider identically whether it exists or not. Declaring a resource in a bucket with an address of its
 * own is ordinary work for the administrator who owns the project, and nothing about the resource is
 * fetched or judged: the declaration is unique within that bucket's namespace, so it cannot be a claim
 * on anybody else's, and a server on an internal network or not yet deployed is as declarable as any.
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
function canonicalIdentifier(
	input: string,
	trailingSlashSignificant = false
): string {
	const result = canonicalizeResourceIdentifier(input, {
		trailingSlashSignificant
	});
	if (!result.ok) {
		throw new AdminError(
			400,
			result.reason === 'fragment'
				? 'a resource identifier must not carry a fragment'
				: 'a resource identifier must be an absolute URI'
		);
	}
	if (
		isMcpResource(result.identifier) ||
		namesOwnScimEndpoint(result.identifier)
	) {
		throw new AdminError(
			409,
			'that identifier names an audience this server serves itself'
		);
	}
	return result.identifier;
}

/*
 * A bucket's SCIM endpoint is built in (lib/provisioning/token_policy.ts) and held only by that bucket's
 * connections. A declaration of it would never resolve where the built-in arm answers first, and elsewhere it
 * would mint a token every SCIM principal refuses — so it is refused here, where an operator can be told why,
 * rather than accepted as a declaration that silently does nothing. Matched on this server's own origin; a
 * directory's SCIM server elsewhere is somebody else's resource and may be declared.
 */
function namesOwnScimEndpoint(identifier: string): boolean {
	const url = new URL(identifier);
	return (
		url.origin === new URL(ISSUER).origin &&
		(url.pathname === SCIM_BASE_PATH || url.pathname.endsWith(SCIM_BASE_PATH))
	);
}

/*
 * The shared root namespace is a super administrator's to write.
 *
 * Every tenant served at the root — a project with no bucket, or a bucket with no address of its own —
 * shares one issuer and so one namespace, and a resource's own metadata can say it trusts that issuer
 * but not which of those tenants it belongs to. No proof the resource could offer would stop one of
 * them declaring another's server first, so the only rule that closes squatting here is who may write.
 * Edits and removals are held to it too: a tenant that could repoint a declaration it could not have
 * made would have the same reach by another route.
 */
function assertMayWrite(ctx: AdminContext, namespace: string): void {
	if (namespace === ROOT_NAMESPACE && !ctx.roles.includes('super_admin')) {
		throw new AdminError(403, ROOT_DECLARATION_REFUSAL);
	}
}

function acceptedScopes(scopes: string[]): string[] {
	const result = validateScopes(scopes);
	if (!result.ok) {
		throw new AdminError(400, scopeFailureMessage(result.reason, result.value));
	}
	return result.scopes;
}

/*
 * Loads a declared resource by the spelling in the path, and refuses one that belongs to a different
 * project than the path names.
 *
 * Looked up the way a token request looks it up — the exact spelling, then the slash-free one — so a
 * resource whose trailing slash is significant is reachable here by the spelling it was declared with,
 * which canonicalizing with the default options made impossible.
 *
 * The project check still matters: a namespace holds every project of its bucket, so
 * `/projects/A/resources/<B's audience>` would otherwise read — and amend — a sibling project's
 * declaration through a project the caller does legitimately own. A 404 rather than a 403, because from
 * this project's point of view the resource genuinely is not there.
 */
async function loadResource(
	projectId: string,
	namespace: string,
	resourceId: string
) {
	// A malformed or reserved spelling is refused the way a write refuses it, before any lookup.
	canonicalIdentifier(resourceId);
	const resource = await findDeclaredResource(resourceId, namespace);
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

			const identifier = canonicalIdentifier(
				body.identifier,
				body.trailingSlashSignificant
			);
			const scopes = acceptedScopes(body.scopes);
			const namespace = await namespaceOfProject(project);
			assertMayWrite(ctx, namespace);

			/*
			 * Checked before the audit write so a refused declaration leaves no entry describing a change
			 * nobody made — and enforced again by the store, which is where it actually holds: namespace and
			 * identifier are the primary key, so a concurrent duplicate is refused by the datastore rather
			 * than by this read.
			 */
			if (await getProtectedResourceStore().find(namespace, identifier)) {
				throw new AdminError(409, 'that identifier is already declared');
			}

			await recordAdminAudit(ctx, 'resource.create', identifier, {
				ownerGroupId: project.ownerGroupId,
				targetScope: namespace
			});

			try {
				const resource = await getProtectedResourceStore().create({
					namespace,
					identifier,
					projectId: params.id,
					name: body.name,
					scopes,
					tokenFormat: body.tokenFormat,
					accessTokenTTL: body.accessTokenTTL,
					trailingSlashSignificant: body.trailingSlashSignificant
				});
				set.status = 201;
				return resource;
			} catch (error) {
				/*
				 * The primary key refused it between the read above and this write. A conflict rather than a
				 * 500: the caller's request was well-formed, and the answer is the same one the read would
				 * have given a moment earlier. Only that refusal — any other failure is a fault, and mapping
				 * it to "already declared" would hide it behind an answer that is not true.
				 */
				if (isUniqueValueTaken(error)) {
					throw new AdminError(409, 'that identifier is already declared');
				}
				throw error;
			}
		},
		{ body: CreateResourceBody }
	)
	.get(
		'/admin/api/projects/:id/resources/:resourceId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadProject(ctx, params.id);
			return loadResource(
				params.id,
				await namespaceOfProject(project),
				params.resourceId
			);
		}
	)
	/*
	 * Whether the resource's published metadata currently vouches for this declaration — a diagnostic
	 * the console fetches per row after the list has rendered, so a slow or unreachable resource never
	 * holds the list up. Read-only, so not audited, and blocking nothing in any namespace.
	 *
	 * The issuer it must list is the one its tokens carry: the bucket's own when the bucket has an
	 * address, the root's otherwise. `issuerFor` alone would answer `<ISSUER>/<id>` for a bucket with
	 * no address, which no metadata document could ever be asked to name.
	 */
	.get(
		'/admin/api/projects/:id/resources/:resourceId/vouching',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadProject(ctx, params.id);
			const namespace = await namespaceOfProject(project);
			const resource = await loadResource(
				params.id,
				namespace,
				params.resourceId
			);
			const expectedIssuer =
				namespace === ROOT_NAMESPACE
					? ISSUER
					: issuerFor(await issuingBucket(namespace));
			return checkVouching(resource.identifier, expectedIssuer, {
				trailingSlashSignificant: resource.trailingSlashSignificant
			});
		}
	)
	.patch(
		'/admin/api/projects/:id/resources/:resourceId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			const project = await loadProject(ctx, params.id);
			const namespace = await namespaceOfProject(project);
			assertMayWrite(ctx, namespace);
			const { identifier } = await loadResource(
				params.id,
				namespace,
				params.resourceId
			);

			const scopes =
				body.scopes === undefined ? undefined : acceptedScopes(body.scopes);

			// After validation: an entry for a request about to be refused as malformed would describe a
			// change nobody attempted.
			await recordAdminAudit(ctx, 'resource.update', identifier, {
				attributes: Object.keys(body),
				ownerGroupId: project.ownerGroupId,
				targetScope: namespace
			});

			return getProtectedResourceStore().update(namespace, identifier, {
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
			const namespace = await namespaceOfProject(project);
			assertMayWrite(ctx, namespace);
			const { identifier } = await loadResource(
				params.id,
				namespace,
				params.resourceId
			);

			await recordAdminAudit(ctx, 'resource.delete', identifier, {
				ownerGroupId: project.ownerGroupId,
				targetScope: namespace
			});

			await getProtectedResourceStore().destroy(namespace, identifier);
			set.status = 204;
			return null;
		}
	);
