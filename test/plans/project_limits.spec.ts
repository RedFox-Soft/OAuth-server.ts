import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adapter,
	adminAuditStore,
	getBucketStore
} from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { AccessToken } from 'lib/models/access_token.ts';
import { Client } from 'lib/models/client.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { BUILT_IN_PLANS } from 'lib/consts/plans.ts';
import { elysia } from 'lib/index.ts';
import { rpc, call as tool } from '../mcp/rpc.ts';
import {
	call,
	createProject,
	freshSlug,
	idOf,
	refusalOf,
	storeCatalogue,
	storeFree,
	superAdmin,
	tenant,
	withPlans,
	type Caller
} from './admin.ts';

let operator: Caller;

const APPLICATION = {
	grantTypes: ['client_credentials'],
	tokenEndpointAuthMethod: 'client_secret_basic'
};

function addApplication(caller: Caller, projectId: string) {
	return call(
		'POST',
		`/admin/api/projects/${projectId}/clients`,
		caller.cookie,
		APPLICATION
	);
}

function declareApi(caller: Caller, projectId: string) {
	return call(
		'POST',
		`/admin/api/projects/${projectId}/resources`,
		caller.cookie,
		{
			identifier: `https://${freshSlug('api')}.example.com/`,
			name: 'API',
			scopes: ['things:read']
		}
	);
}

/* With plans on, a tenant's project on Free is given its address name. */
async function projectFor(owner: Caller): Promise<string> {
	return idOf(await createProject(owner));
}

async function fill(
	add: () => Promise<{ status: number }>,
	count: number
): Promise<void> {
	for (let i = 0; i < count; i += 1) {
		const added = await add();
		if (added.status !== 201) {
			throw new Error(`setup creation answered ${String(added.status)}`);
		}
	}
}

async function auditCount(): Promise<number> {
	return (await adminAuditStore.list({})).entries.length;
}

/**
 * @proves A tenant's project on Free refuses the application and the API one past its plan's limits with an
 * answer that names the limit, the plan and the numbers, writes nothing and leaves no audit entry; applications
 * that registered themselves are not counted; a project already over its limits keeps working; and neither a super
 * administrator nor an instance with plans off is limited.
 */
describe('a project’s applications and APIs on its plan', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'plans' });
		await ensureAdminSeed();
		operator = await superAdmin();
	});

	beforeEach(async () => {
		forgetBucketAddresses();
		await storeCatalogue([...BUILT_IN_PLANS]);
		await withPlans(operator, true);
	});

	it('refuses the eleventh application on Free, naming the limit, the plan and the numbers', async () => {
		const owner = await tenant();
		const id = await projectFor(owner);
		await fill(() => addApplication(owner, id), 10);

		const refusal = refusalOf(await addApplication(owner, id));

		expect(refusal.code).toBe('plan_limit');
		expect(refusal.limit).toEqual({
			name: 'applicationsPerProject',
			plan: { id: 'free', name: 'Free' },
			count: 10,
			max: 10
		});
	});

	it('refuses the API one past the limit', async () => {
		await storeFree({ apisPerProject: 2 });
		const owner = await tenant();
		const id = await projectFor(owner);
		await fill(() => declareApi(owner, id), 2);

		const refusal = refusalOf(await declareApi(owner, id));

		expect(refusal.limit).toEqual({
			name: 'apisPerProject',
			plan: { id: 'free', name: 'Free' },
			count: 2,
			max: 2
		});
	});

	it('writes nothing and records nothing when it refuses', async () => {
		await storeFree({ applicationsPerProject: 1 });
		const owner = await tenant();
		const id = await projectFor(owner);
		await fill(() => addApplication(owner, id), 1);
		const [clientsBefore, entriesBefore] = [
			(await adapter('Client').findByIndexed('bucketId', id)).length,
			await auditCount()
		];

		await addApplication(owner, id);

		expect([
			(await adapter('Client').findByIndexed('bucketId', id)).length,
			await auditCount()
		]).toEqual([clientsBefore, entriesBefore]);
	});

	it('does not count an application that registered itself', async () => {
		await storeFree({ applicationsPerProject: 1 });
		const owner = await tenant();
		const id = await projectFor(owner);
		await adapter('Client').upsert(`dyn-${id}`, {
			clientId: `dyn-${id}`,
			bucketId: id,
			registeredDynamically: true,
			grantTypes: ['client_credentials']
		});

		expect((await addApplication(owner, id)).status).toBe(201);
	});

	it('keeps a project over its limit working: its applications are edited and get tokens', async () => {
		const owner = await tenant();
		const created0 = await createProject(owner);
		const id = idOf(created0);
		const { slug } = created0.body as { slug: string };
		const created = await addApplication(owner, id);
		const { clientId, secret } = created.body as {
			clientId: string;
			secret: string;
		};
		await storeFree({ applicationsPerProject: 0 });
		ApplicationConfig['clientCredentials.enabled'] = true;

		const edited = await call(
			'PATCH',
			`/admin/api/projects/${id}/clients/${clientId}`,
			owner.cookie,
			{ clientName: 'Renamed' }
		);
		const token = await elysia.handle(
			new Request(`http://e.ly/${slug}/token`, {
				method: 'POST',
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
					authorization: `Basic ${btoa(`${clientId}:${secret}`)}`
				},
				body: 'grant_type=client_credentials'
			})
		);

		expect([edited.status, token.status]).toEqual([200, 200]);
	});

	it('does not limit a super administrator', async () => {
		await storeFree({ applicationsPerProject: 1 });
		const owner = await tenant();
		const id = await projectFor(owner);
		await fill(() => addApplication(owner, id), 1);

		expect((await addApplication(operator, id)).status).toBe(201);
		expect((await addApplication(owner, id)).status).toBe(409);
	});

	it('limits nothing while plans are off', async () => {
		await storeFree({ applicationsPerProject: 1 });
		const owner = await tenant();
		const id = await projectFor(owner);
		await fill(() => addApplication(owner, id), 1);
		await withPlans(operator, false);

		expect((await addApplication(owner, id)).status).toBe(201);
	});

	it('gives an agent the same refusal, with its code and limit', async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await storeFree({ applicationsPerProject: 1 });
		const owner = await tenant();
		const id = await projectFor(owner);
		await fill(() => addApplication(owner, id), 1);
		const at = new AccessToken({
			client: await Client.find(ADMIN_MCP_CLIENT_ID),
			accountId: owner.user._id,
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

		const answered = await rpc(
			tool('client_create', { id, ...APPLICATION }),
			token
		);
		const content = answered.result?.structuredContent as
			Record<string, unknown> | undefined;

		expect(content?.reason).toBe('conflict');
		expect(content?.code).toBe('plan_limit');
		expect(content?.limit).toEqual({
			name: 'applicationsPerProject',
			plan: { id: 'free', name: 'Free' },
			count: 1,
			max: 1
		});
		expect((await getBucketStore().find(id))?.planId).toBe('free');
	});
});
