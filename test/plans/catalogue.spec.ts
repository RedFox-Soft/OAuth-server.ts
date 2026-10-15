import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminAuditStore, getBucketStore } from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { AccessToken } from 'lib/models/access_token.ts';
import { Client } from 'lib/models/client.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { BUILT_IN_PLANS, type Plan } from 'lib/consts/plans.ts';
import type { User } from 'lib/adapters/types.ts';
import { rpc, call as tool } from '../mcp/rpc.ts';
import {
	call,
	createProject,
	idOf,
	storeCatalogue,
	superAdmin,
	tenant,
	withPlans,
	type Caller
} from './admin.ts';

let operator: Caller;

const [free] = BUILT_IN_PLANS;
const STARTER: Plan = {
	id: 'starter',
	name: 'Starter',
	default: false,
	limits: {
		monthlyActiveUsers: 500_000,
		projectsPerAdministrator: 5,
		applicationsPerProject: 50,
		apisPerProject: 50
	},
	features: { enterpriseSignIn: true, customSlug: true, customDomain: false }
};

interface Listed {
	plans: (Plan & { projects: number })[];
}

async function actions(): Promise<string[]> {
	return (await adminAuditStore.list({})).entries.map((entry) => entry.action);
}

async function agentFor(user: User): Promise<string> {
	ApplicationConfig['mcp.enabled'] = true;
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId: user._id,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = await at.save();
	await rpc(
		{
			jsonrpc: '2.0',
			id: 0,
			method: 'initialize',
			params: {
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			}
		},
		token
	);
	return token;
}

/**
 * @proves A super administrator reads, adds, changes and removes plans, chooses the default and moves a tenant's
 * project to another plan — each recorded in the audit trail, the default and a plan in use protected from removal,
 * a System project never given one — and the tenant's next creation follows the new plan; a tenant can do none of
 * it, from the console or through an agent.
 */
describe('the plan catalogue and a project’s plan', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'plans' });
		await ensureAdminSeed();
		operator = await superAdmin();
	});

	describe('on an instance nobody has configured', () => {
		it('holds exactly Free, the default', async () => {
			const listed = await call('GET', '/admin/api/plans', operator.cookie);

			expect((listed.body as Listed).plans).toEqual([{ ...free, projects: 0 }]);
		});
	});

	describe('once configured', () => {
		beforeEach(async () => {
			forgetBucketAddresses();
			await storeCatalogue([...BUILT_IN_PLANS]);
			await withPlans(operator, true);
		});

		it('adds, changes and removes a plan, recording each', async () => {
			const created = await call(
				'POST',
				'/admin/api/plans',
				operator.cookie,
				STARTER
			);
			const changed = await call(
				'PATCH',
				'/admin/api/plans/starter',
				operator.cookie,
				{ name: 'Starter 2026', limits: { applicationsPerProject: 60 } }
			);
			const removed = await call(
				'DELETE',
				'/admin/api/plans/starter',
				operator.cookie
			);

			expect([created.status, changed.status, removed.status]).toEqual([
				201, 200, 204
			]);
			expect((changed.body as Plan).limits.applicationsPerProject).toBe(60);
			expect((changed.body as Plan).limits.apisPerProject).toBe(50);
			const recorded = await actions();
			expect(
				['plan.create', 'plan.update', 'plan.delete'].filter(
					(action) => !recorded.includes(action)
				)
			).toEqual([]);
		});

		it('moves the default to the plan made default, and will not leave none', async () => {
			await call('POST', '/admin/api/plans', operator.cookie, STARTER);

			const made = await call(
				'PATCH',
				'/admin/api/plans/starter',
				operator.cookie,
				{
					default: true
				}
			);
			const unmade = await call(
				'PATCH',
				'/admin/api/plans/starter',
				operator.cookie,
				{
					default: false
				}
			);
			const listed = (await call('GET', '/admin/api/plans', operator.cookie))
				.body as Listed;

			expect([made.status, unmade.status]).toEqual([200, 400]);
			expect(
				listed.plans.filter((plan) => plan.default).map((plan) => plan.id)
			).toEqual(['starter']);
		});

		it('refuses to remove the default plan or a plan a project is on, saying how many', async () => {
			await call('POST', '/admin/api/plans', operator.cookie, STARTER);
			const owner = await tenant();
			const id = idOf(await createProject(owner));
			await call('PUT', `/admin/api/projects/${id}/plan`, operator.cookie, {
				planId: 'starter'
			});

			const theDefault = await call(
				'DELETE',
				'/admin/api/plans/free',
				operator.cookie
			);
			const inUse = await call(
				'DELETE',
				'/admin/api/plans/starter',
				operator.cookie
			);

			expect([theDefault.status, inUse.status]).toEqual([409, 409]);
			expect((inUse.body as { blockers?: unknown }).blockers).toEqual([
				{ kind: 'project', count: 1 }
			]);
		});

		it('moves a tenant’s project to a larger plan, recorded with both plans, and the tenant’s next creation follows it', async () => {
			await call('POST', '/admin/api/plans', operator.cookie, STARTER);
			const owner = await tenant();
			idOf(await createProject(owner));
			const id = idOf(await createProject(owner));
			const refusedBefore = (await createProject(owner)).status;

			const moved = await call(
				'PUT',
				`/admin/api/projects/${id}/plan`,
				operator.cookie,
				{
					planId: 'starter'
				}
			);
			const entry = (await adminAuditStore.list({})).entries.find(
				(e) => e.action === 'bucket.plan' && e.targetId === id
			);
			const renamed = await call(
				'POST',
				`/admin/api/projects/${id}/address`,
				owner.cookie,
				{
					slug: `own-${Math.random().toString(36).slice(2, 8)}`
				}
			);

			expect([refusedBefore, moved.status]).toEqual([409, 200]);
			expect((await getBucketStore().find(id))?.planId).toBe('starter');
			expect([entry?.from, entry?.to]).toEqual(['free', 'starter']);
			expect((renamed.body as { code?: string }).code).toBeUndefined();
		});

		it('gives a System project no plan', async () => {
			const answered = await call(
				'PUT',
				`/admin/api/projects/${DEFAULT_BUCKET_ID}/plan`,
				operator.cookie,
				{ planId: 'free' }
			);

			expect(answered.status).toBe(409);
			expect(
				(await getBucketStore().find(DEFAULT_BUCKET_ID))?.planId
			).toBeUndefined();
		});

		it('refuses a tenant every catalogue and plan route', async () => {
			const owner = await tenant();
			const id = idOf(await createProject(owner));

			const statuses = [
				(await call('GET', '/admin/api/plans', owner.cookie)).status,
				(await call('POST', '/admin/api/plans', owner.cookie, STARTER)).status,
				(
					await call('PATCH', '/admin/api/plans/free', owner.cookie, {
						name: 'Mine'
					})
				).status,
				(await call('DELETE', '/admin/api/plans/free', owner.cookie)).status,
				(
					await call('PUT', `/admin/api/projects/${id}/plan`, owner.cookie, {
						planId: 'free'
					})
				).status
			];

			expect(statuses).toEqual([403, 403, 403, 403, 403]);
		});

		it('refuses a tenant’s agent the plan tools, and asks a super administrator’s to confirm a change', async () => {
			const owner = await tenant();
			const tenantAgent = await agentFor(owner.user);
			const operatorAgent = await agentFor(operator.user);

			const tenantRead = await rpc(tool('plan_list'), tenantAgent);
			const operatorRead = await rpc(tool('plan_list'), operatorAgent);
			const operatorWrite = await rpc(
				tool('plan_create', { ...STARTER }),
				operatorAgent
			);

			expect(tenantRead.result?.structuredContent?.reason).toBe('forbidden');
			expect(operatorRead.result?.isError).not.toBe(true);
			expect(operatorRead.result?.structuredContent?.result).toBeDefined();
			expect(operatorWrite.result?.structuredContent?.status).toBe(
				'confirmation_required'
			);
		});
	});
});
