import { describe, it, expect, beforeAll, beforeEach, spyOn } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { Grant } from 'lib/models/grant.js';
import { Client } from 'lib/models/client.js';
import { AccessToken } from 'lib/models/access_token.js';
import {
	adapter,
	adminSessionStore,
	getBucketStore,
	getProjectStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';

// User Story 4 — an operator can see the consequences, before and after.
//
// The reason these are structured fields rather than prose: the console's dialogs and an MCP agent both
// consume the same management API, and neither should have to parse a sentence to list what a deletion
// will destroy.

interface Blocker {
	kind: string;
	count: number;
	ids?: string[];
}

describe('deletion reporting', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ensureAdminSeed();
	});

	async function superAdminCookie(): Promise<string> {
		const admin = await getUserStore(ADMIN_BUCKET_ID).create(
			`sa-${Math.random()}@x.io`,
			'hash',
			['super_admin']
		);
		const session = await sessionFor(admin);
		return `${ADMIN_SESSION_COOKIE}=${session._id}`;
	}

	async function liveClient(): Promise<string> {
		const clientId = `rep-${Math.random().toString(36).slice(2)}`;
		await adapter('Client').upsert(clientId, {
			clientId,
			clientSecret: 'secret',
			grantTypes: ['authorization_code'],
			responseTypes: ['code'],
			redirectUris: [`https://${clientId}.example.com/cb`]
		});
		return clientId;
	}

	/* Narrowed from `unknown`: Eden's response type differs per route, so naming one shape here would
	 * only fit one call site. */
	function bodyOf<
		T = { error?: string; message?: string; blockers?: Blocker[] }
	>(response: unknown): T | undefined {
		if (typeof response !== 'object' || response === null) return undefined;
		const { data, error } = response as {
			data?: unknown;
			error?: { value?: unknown } | null;
		};
		return (data ?? error?.value) as T | undefined;
	}

	it('lists the blocking client ids on a refused project deletion', async () => {
		const cookie = await superAdminCookie();
		const first = await liveClient();
		const second = await liveClient();
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'P',
			slug: `p-${Math.random()}`,
			clientIds: [first, 'ghost', second]
		});

		const res = await agent.admin.api
			.projects({ id: project._id })
			.delete(undefined, { headers: { cookie } });

		expect(res.status).toBe(409);
		const body = bodyOf(res);
		// The existing envelope is unchanged; blockers ride alongside it.
		expect(body?.error).toBe('admin_error');
		expect(body?.blockers).toEqual([
			{ kind: 'client', count: 2, ids: [first, second] }
		]);
	});

	it('reports only a count for end-user blockers, never identifiers', async () => {
		const cookie = await superAdminCookie();
		const bucket = await getBucketStore().create({
			name: `b-${Math.random()}`,
			roles: [],
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const store = getUserStore(bucket._id);
		const one = await store.create('one@example.com', 'hash');
		await store.create('two@example.com', 'hash');

		const res = await agent.admin.api
			.buckets({ id: bucket._id })
			.delete(undefined, { headers: { cookie } });

		expect(res.status).toBe(409);
		const body = bodyOf(res);
		expect(body?.blockers).toEqual([{ kind: 'enduser', count: 2 }]);
		// A bucket can hold thousands of accounts; their identities are not the caller's business.
		expect(JSON.stringify(body)).not.toContain(one._id);
		expect(JSON.stringify(body)).not.toContain('one@example.com');
	});

	it('reports per-area counts on a successful client deletion', async () => {
		const cookie = await superAdminCookie();
		const clientId = await liveClient();
		const client = await Client.tryFind(clientId);
		if (!client) throw new Error('client did not resolve');
		const accountId = 'reporting-account';

		const grant = new Grant({ clientId, accountId });
		grant.addOIDCScope('openid');
		const grantId = await grant.save();
		await new AccessToken({
			client,
			accountId,
			grantId,
			scope: 'openid'
		}).save();
		await new AccessToken({
			client,
			accountId,
			grantId,
			scope: 'openid'
		}).save();

		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'P',
			slug: `p-${Math.random()}`,
			clientIds: [clientId]
		});
		const res = await agent.admin.api
			.projects({ id: project._id })
			.clients({ clientId })
			.delete(undefined, { headers: { cookie } });

		expect(res.status).toBe(200);
		const body = res.data as { ok: boolean; destroyed: Record<string, number> };
		expect(body.ok).toBe(true);
		expect(body.destroyed.AccessToken).toBe(2);
		expect(body.destroyed.Grant).toBe(1);
		// Areas that swept nothing are still reported, so the answer describes every area attempted.
		expect(body.destroyed.ClientCredentials).toBe(0);
		expect(body.destroyed.RegistrationAccessToken).toBe(0);
	});

	it('reports per-area counts on a successful end-user deletion', async () => {
		const cookie = await superAdminCookie();
		const bucket = await getBucketStore().create({
			name: `b-${Math.random()}`,
			roles: [],
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const user = await getUserStore(bucket._id).create(
			'counted@example.com',
			'hash'
		);
		const grant = new Grant({ clientId: 'doomed', accountId: user._id });
		grant.addOIDCScope('openid');
		await grant.save();

		const res = await agent.admin.api
			.buckets({ id: bucket._id })
			.users({ uid: user._id })
			.delete(undefined, { headers: { cookie } });

		expect(res.status).toBe(200);
		const body = res.data as { ok: boolean; destroyed: Record<string, number> };
		expect(body.destroyed.Grant).toBe(1);
		expect(body.destroyed.Session).toBe(0);
	});

	// The principal is already gone when a sweep fails, so the honest answer names what survived rather
	// than pretending the deletion did not happen.
	it('answers 500 naming the areas that failed, and still sweeps the rest', async () => {
		const cookie = await superAdminCookie();
		const clientId = await liveClient();
		const client = await Client.tryFind(clientId);
		if (!client) throw new Error('client did not resolve');
		const accountId = 'failing-account';

		const grant = new Grant({ clientId, accountId });
		grant.addOIDCScope('openid');
		const grantId = await grant.save();
		const at = new AccessToken({
			client,
			accountId,
			grantId,
			scope: 'openid'
		});
		await at.save();

		const grantAdapter = adapter('Grant');
		const spy = spyOn(grantAdapter, 'destroyByOwner').mockRejectedValue(
			new Error('storage unavailable')
		);
		try {
			const project = await getProjectStore().create({
				ownerGroupId: UNASSIGNED_GROUP_ID,
				name: 'P',
				slug: `p-${Math.random()}`,
				clientIds: [clientId]
			});
			const res = await agent.admin.api
				.projects({ id: project._id })
				.clients({ clientId })
				.delete(undefined, { headers: { cookie } });

			expect(res.status).toBe(500);
			const body = bodyOf<{ failedAreas?: string[] }>(res);
			expect(body?.failedAreas).toEqual(['Grant']);
		} finally {
			spy.mockRestore();
		}

		// One area failing must not abort the others: the access token is gone, and so is the client.
		expect(await adapter('AccessToken').find(at.jti)).toBeUndefined();
		expect(await adapter('Client').find(clientId)).toBeUndefined();
		// And the grant survived, which is exactly what the 500 said.
		expect(await adapter('Grant').find(grantId)).toBeDefined();
	});
});
