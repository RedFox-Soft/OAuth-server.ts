import { Elysia } from 'elysia';
import { adapter } from '../../adapters/index.js';
import {
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { ADMIN_BUCKET_ID } from '../consts.js';
import { isAdministratorsApplication } from '../administrators_application.js';
import {
	CreateAdministratorApplicationBody,
	UpdateAdministratorApplicationBody
} from './schema.js';
import {
	createClient,
	getClientView,
	updateClient,
	rotateSecret,
	deleteClientRecord,
	type AdminClientView
} from '../clients/service.js';
import { recordAdminAudit } from '../audit/record.js';
import { cascadeForClient } from '../../helpers/cascade.js';
import nanoid from '../../helpers/nanoid.js';
import { ADMIN_REQUEST_BUCKET, issuerFor } from '../../configs/issuer.js';
import { readClientUsage } from '../../models/client/usage.js';

/*
 * Applications in the administrators' project (specs/109): a super administrator registers one for an
 * internal tool so it can sign the instance's administrators in. Routes of their own rather than the project
 * application routes, which keep refusing this project: an agent may read these but not write them, and that is
 * decided per route in the MCP catalogue.
 *
 * Super administrators only, because choosing which outside service may sign administrators in is an
 * instance-wide act — as configuring the administrators' identity providers is. No plan is consulted: this
 * project belongs to the instance, not to a team's plan.
 */

const SIGN_IN = 'authorization_code';
const REFRESH = 'refresh_token';

/* Edge words for what the service stores: the grants become one switch, since sign-in is the only choice. */
async function viewOf(view: AdminClientView) {
	const issuer = issuerFor(ADMIN_REQUEST_BUCKET);
	return {
		clientId: view.clientId,
		clientName: view.clientName,
		redirectUris: view.redirectUris,
		postLogoutRedirectUris: view.postLogoutRedirectUris,
		tokenEndpointAuthMethod: view.tokenEndpointAuthMethod,
		refreshTokens: view.grantTypes.includes(REFRESH),
		requireConsent: view.requireConsent,
		hasSecret: view.hasSecret,
		issuer,
		discoveryUrl: `${issuer}/.well-known/openid-configuration`,
		lastUsed: await readClientUsage(view.clientId)
	};
}

/*
 * The application, or 404 — also for the console's and the agent's own clients, which live in the same
 * project and are not these routes' to read or change.
 */
async function applicationOf(clientId: string): Promise<AdminClientView> {
	const view = await getClientView(clientId);
	if (
		!view ||
		!isAdministratorsApplication({ clientId, bucketId: view.projectId })
	) {
		throw new AdminError(404, 'application not found');
	}
	return view;
}

function superAdmin(admin: AdminContext | null): AdminContext {
	const ctx = assertAuth(admin);
	assertSuperAdmin(ctx);
	return ctx;
}

const scope = { bucketId: ADMIN_BUCKET_ID };

export const administratorApplicationRoutes = new Elysia({
	name: 'admin-administrator-applications'
})
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/administrators/applications', async ({ admin }) => {
		superAdmin(admin);
		const stored = await adapter('Client').findByIndexed(
			'bucketId',
			ADMIN_BUCKET_ID
		);
		const applications = [];
		for (const record of stored) {
			const clientId = String(record.clientId);
			if (!isAdministratorsApplication({ clientId, bucketId: ADMIN_BUCKET_ID }))
				continue;
			const view = await getClientView(clientId);
			if (view) applications.push(await viewOf(view));
		}
		return { applications };
	})
	.post(
		'/admin/api/administrators/applications',
		async ({ admin, body, set }) => {
			const ctx = superAdmin(admin);
			// Allocated here so the entry names the application that is about to exist.
			const clientId = nanoid();
			await recordAdminAudit(ctx, 'admin.application.create', clientId, scope);
			const { view, secret } = await createClient(ADMIN_BUCKET_ID, {
				clientId,
				clientName: body.clientName,
				applicationType: 'web',
				grantTypes:
					body.refreshTokens === false ? [SIGN_IN] : [SIGN_IN, REFRESH],
				redirectUris: body.redirectUris,
				postLogoutRedirectUris: body.postLogoutRedirectUris ?? [],
				tokenEndpointAuthMethod:
					body.tokenEndpointAuthMethod ?? 'client_secret_basic',
				requireConsent: body.requireConsent ?? false,
				...(body.jwks === undefined ? {} : { jwks: body.jwks }),
				...(body.jwksUri === undefined ? {} : { jwksUri: body.jwksUri })
			});
			set.status = 201;
			return { ...(await viewOf(view)), secret };
		},
		{ body: CreateAdministratorApplicationBody }
	)
	.get(
		'/admin/api/administrators/applications/:clientId',
		async ({ admin, params }) => {
			superAdmin(admin);
			return viewOf(await applicationOf(params.clientId));
		}
	)
	.patch(
		'/admin/api/administrators/applications/:clientId',
		async ({ admin, params, body }) => {
			const ctx = superAdmin(admin);
			await applicationOf(params.clientId);
			await recordAdminAudit(ctx, 'admin.application.update', params.clientId, {
				...scope,
				attributes: Object.keys(body)
			});
			const { refreshTokens, ...rest } = body;
			const { view } = await updateClient(params.clientId, {
				...rest,
				...(refreshTokens === undefined
					? {}
					: { grantTypes: refreshTokens ? [SIGN_IN, REFRESH] : [SIGN_IN] })
			});
			return viewOf(view);
		},
		{ body: UpdateAdministratorApplicationBody }
	)
	.post(
		'/admin/api/administrators/applications/:clientId/secret',
		async ({ admin, params }) => {
			const ctx = superAdmin(admin);
			await applicationOf(params.clientId);
			// The rotation is the recorded fact; the secret itself never enters the trail.
			await recordAdminAudit(
				ctx,
				'admin.application.secret.rotate',
				params.clientId,
				scope
			);
			const secret = await rotateSecret(params.clientId);
			return { clientId: params.clientId, secret };
		}
	)
	.delete(
		'/admin/api/administrators/applications/:clientId',
		async ({ admin, params }) => {
			const ctx = superAdmin(admin);
			await applicationOf(params.clientId);
			await recordAdminAudit(
				ctx,
				'admin.application.delete',
				params.clientId,
				scope
			);
			await deleteClientRecord(params.clientId);
			// As for a project application: the principal goes first, then everything it held.
			const cascade = await cascadeForClient(params.clientId);
			if (cascade.failedAreas.length > 0) {
				throw new AdminError(
					500,
					`application deleted, but its records survive in: ${cascade.failedAreas.join(', ')}`,
					{ failedAreas: cascade.failedAreas }
				);
			}
			return { ok: true };
		}
	);
