import { Elysia } from 'elysia';

import {
	getConnectedAccountStore,
	getUserStore
} from '../../adapters/index.js';
import { agentsByAccount } from '../../connected_services/consent.js';
import type { UserBucket } from '../../adapters/types.js';
import {
	assertAuth,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../auth/rbac.js';
import { loadBucketForEdit, loadBucketForUsers } from '../buckets/access.js';
import { recordAdminAudit } from '../audit/record.js';
import { scheduledBucketGuard } from '../buckets/scheduled_guard.js';
import { assertConnectedServiceRoom } from '../../plans/enforce.js';
import {
	disconnect,
	listForPerson
} from '../../connected_services/accounts.js';
import { CreateServiceBody, UpdateServiceBody } from './schema.js';
import {
	assertKeyringInUse,
	assertSignInLink,
	catalogueView,
	createService,
	deleteService,
	findService,
	present,
	presentAll,
	updateService
} from './service.js';

function ownedBy(bucket: Pick<UserBucket, 'ownerGroupId'>): {
	ownerGroupId: string;
} {
	return { ownerGroupId: bucket.ownerGroupId };
}

/*
 * Read with the project's people (`loadBucketForUsers`), as its outside servers are: a connected service exists for
 * the people, and the Administrators project, which signs people in to the console and nothing else, has none, so
 * a console page never offers what a write would refuse.
 */
function readable(ctx: AdminContext, id: string): Promise<UserBucket> {
	return loadBucketForUsers(ctx, id);
}

/*
 * A project's connected services and its people's connected accounts (specs/117 contracts/admin-surface.md).
 *
 * Every mutation is audit-first, after authorization and after the refusals that can stop it (the keyring, the
 * plan), with `attributes` naming the fields set and never their values. Published to agents through
 * lib/mcp/catalogue.ts; the two deletions are high there.
 */
export const connectedServiceAdminRoutes = new Elysia({
	name: 'admin-connected-services'
})
	.use(resolveAdmin)
	/*
	 * Mounted as a statement of its own (lib/admin/routes.ts, for the type-depth reason given there), so the chain's
	 * guard does not reach these routes: a write into a bucket scheduled for deletion is refused here as everywhere.
	 */
	.use(scheduledBucketGuard)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get(
		'/admin/api/projects/:id/connected-services',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			return presentAll(await readable(ctx, params.id));
		}
	)
	.get(
		'/admin/api/projects/:id/connected-services/catalogue',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			await readable(ctx, params.id);
			return catalogueView();
		}
	)
	.get(
		'/admin/api/projects/:id/connected-services/:serviceId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await readable(ctx, params.id);
			return present(bucket, findService(bucket, params.serviceId));
		}
	)
	.post(
		'/admin/api/projects/:id/connected-services',
		async ({ admin, params, body, set }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			assertKeyringInUse();
			await assertConnectedServiceRoom(ctx, bucket);
			if (body.signInProviderId) {
				assertSignInLink(
					bucket,
					{
						id: '',
						kind: body.kind,
						...(body.catalogueId ? { catalogueId: body.catalogueId } : {}),
						...(body.issuer ? { issuer: body.issuer } : {}),
						...(body.tenant ? { tenant: body.tenant } : {}),
						clientId: body.clientId,
						scopes: [],
						displayName: '',
						createdAt: '',
						updatedAt: ''
					},
					body.signInProviderId
				);
			}
			await recordAdminAudit(ctx, 'connected.service.create', params.id, {
				attributes: Object.keys(body),
				...(body.signInProviderId
					? { signInProviderId: body.signInProviderId }
					: {}),
				...ownedBy(bucket)
			});
			const created = await createService(bucket, body);
			set.status = 201;
			return present(bucket, created);
		},
		{ body: CreateServiceBody }
	)
	.patch(
		'/admin/api/projects/:id/connected-services/:serviceId',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			assertKeyringInUse();
			const current = findService(bucket, params.serviceId);
			/* Refused before the trail is written, so a link that cannot exist is never recorded (specs/120). */
			if (typeof body.signInProviderId === 'string') {
				assertSignInLink(bucket, current, body.signInProviderId);
			}
			await recordAdminAudit(ctx, 'connected.service.update', params.id, {
				attributes: Object.keys(body),
				serviceId: params.serviceId,
				/* Who may now obtain its tokens (specs/118 R4), ids only. */
				...(body.applications ? { to: body.applications.join(' ') } : {}),
				...(body.signInProviderId !== undefined
					? { signInProviderId: body.signInProviderId }
					: {}),
				...ownedBy(bucket)
			});
			return present(
				bucket,
				await updateService(bucket, params.serviceId, body)
			);
		},
		{ body: UpdateServiceBody }
	)
	.delete(
		'/admin/api/projects/:id/connected-services/:serviceId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForEdit(ctx, params.id);
			findService(bucket, params.serviceId);
			await recordAdminAudit(ctx, 'connected.service.delete', params.id, {
				serviceId: params.serviceId,
				...ownedBy(bucket)
			});
			const disconnected = await deleteService(bucket, params.serviceId);
			return { deleted: true, disconnected };
		}
	)
	/* `:uid`, as the other end-user routes name that slot, which the router requires. */
	.get(
		'/admin/api/projects/:id/users/:uid/connected-accounts',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const user = await getUserStore(params.id).find(params.uid);
			if (!user) throw new AdminError(404, 'user not found');
			// Never a token: the view carries the account's identity, scopes, dates and status only.
			const views = await listForPerson(bucket, params.uid);
			const agents = await agentsByAccount(
				bucket,
				params.uid,
				await getConnectedAccountStore().listByAccount(bucket._id, params.uid)
			);
			/* Which applications the person let use each account, and when each last did (specs/118 FR-024). */
			return {
				accounts: views.map((view) => ({
					...view,
					agents: (agents.get(view.id) ?? []).map((agent) => ({
						clientId: agent.clientId,
						...(agent.lastUsedAt === undefined
							? {}
							: { lastUsedAt: new Date(agent.lastUsedAt * 1000).toISOString() })
					}))
				}))
			};
		}
	)
	.delete(
		'/admin/api/projects/:id/users/:uid/connected-accounts/:accountId',
		async ({ admin, params }) => {
			const ctx = assertAuth(admin);
			const bucket = await loadBucketForUsers(ctx, params.id);
			const accounts = await listForPerson(bucket, params.uid);
			if (!accounts.some((account) => account.id === params.accountId)) {
				throw new AdminError(404, 'connected account not found');
			}
			await recordAdminAudit(ctx, 'connected.account.delete', params.uid, {
				targetScope: params.id,
				connectedAccountId: params.accountId,
				...ownedBy(bucket)
			});
			await disconnect({
				bucket,
				accountId: params.uid,
				connectedAccountId: params.accountId,
				by: 'administrator'
			});
			return { deleted: true };
		}
	);
