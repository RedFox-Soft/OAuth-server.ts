import { Elysia } from 'elysia';
import { getBucketStore, getPlanCatalogueStore } from '../../adapters/index.js';
import type { Plan } from '../../consts/plans.js';
import {
	assertAuth,
	assertSuperAdmin,
	AdminError,
	adminErrorBody,
	resolveAdmin
} from '../auth/rbac.js';
import { recordAdminAudit } from '../audit/record.js';
import { UNASSIGNED_GROUP_ID } from '../consts.js';
import { catalogue, planOf } from '../../plans/catalogue.js';
import {
	CreatePlanBody,
	SetProjectPlanBody,
	UpdatePlanBody
} from './schema.js';

/*
 * The plan catalogue and a project's plan (specs/102). Every route is a super administrator's: a plan decides what
 * a tenant may create, so no tenant changes one, and a tenant reads its own project's plan through the project's
 * summary instead of the catalogue.
 *
 * The catalogue is written whole. Its invariants — exactly one default, unique ids, no plan removed while a project
 * names it or while it is the default — are checked here, before the audit entry, so a refused change leaves none.
 */

/* How many projects record each plan. A System project records none, and is not counted. */
async function projectsPerPlan(): Promise<Map<string, number>> {
	const counts = new Map<string, number>();
	for (const bucket of await getBucketStore().list()) {
		if (bucket.ownerGroupId === UNASSIGNED_GROUP_ID || !bucket.planId) continue;
		counts.set(bucket.planId, (counts.get(bucket.planId) ?? 0) + 1);
	}
	return counts;
}

async function save(plans: readonly Plan[]): Promise<void> {
	await getPlanCatalogueStore().set({ plans: [...plans] });
}

function planNotFound(): AdminError {
	return new AdminError(404, 'plan not found');
}

export const planRoutes = new Elysia({ name: 'admin-plans' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return adminErrorBody(error);
		}
	})
	.get('/admin/api/plans', async ({ admin }) => {
		assertSuperAdmin(assertAuth(admin));
		const counts = await projectsPerPlan();
		return {
			plans: (await catalogue()).map((plan) => ({
				...plan,
				projects: counts.get(plan.id) ?? 0
			}))
		};
	})
	.post(
		'/admin/api/plans',
		async ({ admin, body, set }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			const plans = await catalogue();
			if (plans.some((plan) => plan.id === body.id)) {
				throw new AdminError(409, `a plan '${body.id}' already exists`, {
					field: 'id'
				});
			}
			await recordAdminAudit(ctx, 'plan.create', body.id, {
				attributes: [
					'name',
					'limits',
					'features',
					...(body.default ? ['default'] : [])
				]
			});
			await save([
				...plans.map((plan) =>
					body.default ? { ...plan, default: false } : plan
				),
				body
			]);
			set.status = 201;
			return body;
		},
		{ body: CreatePlanBody }
	)
	.patch(
		'/admin/api/plans/:id',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			assertSuperAdmin(ctx);
			if (body.default === false) {
				throw new AdminError(
					400,
					'a catalogue always has a default plan: make another plan the default instead',
					{ field: 'default' }
				);
			}
			const plans = await catalogue();
			const current = plans.find((plan) => plan.id === params.id);
			if (!current) throw planNotFound();
			const next: Plan = {
				...current,
				...(body.name === undefined ? {} : { name: body.name }),
				...(body.default ? { default: true } : {}),
				limits: { ...current.limits, ...body.limits },
				features: { ...current.features, ...body.features }
			};
			await recordAdminAudit(ctx, 'plan.update', params.id, {
				attributes: Object.keys(body)
			});
			await save(
				plans.map((plan) =>
					plan.id === params.id
						? next
						: body.default
							? { ...plan, default: false }
							: plan
				)
			);
			return next;
		},
		{ body: UpdatePlanBody }
	)
	.delete('/admin/api/plans/:id', async ({ admin, params, set }) => {
		const ctx = assertAuth(admin);
		assertSuperAdmin(ctx);
		const plans = await catalogue();
		const current = plans.find((plan) => plan.id === params.id);
		if (!current) throw planNotFound();
		if (current.default) {
			throw new AdminError(
				409,
				'this is the default plan: make another plan the default before removing it'
			);
		}
		const count = (await projectsPerPlan()).get(params.id) ?? 0;
		if (count > 0) {
			throw new AdminError(
				409,
				`${String(count)} project${count === 1 ? ' is' : 's are'} on this plan: move ${count === 1 ? 'it' : 'them'} to another plan first`,
				{ blockers: [{ kind: 'project', count }] }
			);
		}
		await recordAdminAudit(ctx, 'plan.delete', params.id);
		await save(plans.filter((plan) => plan.id !== params.id));
		set.status = 204;
		return undefined;
	})
	.put(
		'/admin/api/projects/:id/plan',
		async ({ admin, params, body }) => {
			const ctx = assertAuth(admin);
			/* Before the project is looked up, so nobody without the right learns whether it exists. */
			assertSuperAdmin(ctx);
			const bucket = await getBucketStore().find(params.id);
			if (!bucket) throw new AdminError(404, 'project not found');
			if (bucket.ownerGroupId === UNASSIGNED_GROUP_ID) {
				throw new AdminError(
					409,
					'a System project carries no plan and is never limited'
				);
			}
			const plans = await catalogue();
			const plan = plans.find((candidate) => candidate.id === body.planId);
			if (!plan) throw planNotFound();
			const from = planOf(bucket, plans)?.id;
			if (from === plan.id && bucket.planId === plan.id) {
				return { id: bucket._id, planId: plan.id };
			}
			await recordAdminAudit(ctx, 'bucket.plan', bucket._id, {
				from,
				to: plan.id,
				ownerGroupId: bucket.ownerGroupId
			});
			await getBucketStore().setPlan(bucket._id, plan.id);
			return { id: bucket._id, planId: plan.id };
		},
		{ body: SetProjectPlanBody }
	);
