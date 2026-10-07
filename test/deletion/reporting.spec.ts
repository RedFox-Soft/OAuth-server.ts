import { describe, it, expect, beforeAll, beforeEach, spyOn } from 'bun:test';
import { Type, type Static, type TSchema } from '@sinclair/typebox';

import bootstrap, { agent } from '../test_helper.js';
import { Grant } from 'lib/models/grant.js';
import { Client } from 'lib/models/client.js';
import { AccessToken } from 'lib/models/access_token.js';
import {
	adapter,
	getBucketStore,
	getProjectStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { shaped } from 'test/shape.js';
import { createAdministrator } from '../administrators.ts';

// User Story 4 — an operator can see the consequences, before and after.
//
// The reason these are structured fields rather than prose: the console's dialogs and an MCP agent both
// consume the same management API, and neither should have to parse a sentence to list what a deletion
// will destroy.

const Blocker = Type.Object({
	kind: Type.String(),
	count: Type.Number(),
	ids: Type.Optional(Type.Array(Type.String()))
});

const Refusal = Type.Object({
	error: Type.Optional(Type.String()),
	message: Type.Optional(Type.String()),
	blockers: Type.Optional(Type.Array(Blocker))
});

const Swept = Type.Object({
	ok: Type.Boolean(),
	destroyed: Type.Record(Type.String(), Type.Number())
});

const Answer = Type.Object({
	data: Type.Optional(Type.Unknown()),
	error: Type.Optional(
		Type.Union([
			Type.Null(),
			Type.Object({ value: Type.Optional(Type.Unknown()) })
		])
	)
});

/**
 * @proves A deletion tells the operator what blocked it or what it removed, per area, without
 * naming end-users, and reports a partial failure rather than hiding it.
 */
describe('deletion reporting', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ensureAdminSeed();
	});

	async function superAdminCookie(): Promise<string> {
		const admin = await createAdministrator(
			'super',
			`sa-${Math.random()}@x.io`
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
	function bodyOf<S extends TSchema>(schema: S, response: unknown): Static<S> {
		const { data, error } = shaped(Answer, response);
		return shaped(schema, data ?? error?.value);
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
		const body = bodyOf(Refusal, res);
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
			ownerGroupId: UNASSIGNED_GROUP_ID
		});
		const store = getUserStore(bucket._id);
		const one = await store.create('one@example.com', 'hash');
		await store.create('two@example.com', 'hash');

		const res = await agent.admin.api
			.buckets({ id: bucket._id })
			.delete(undefined, { headers: { cookie } });

		expect(res.status).toBe(409);
		const body = bodyOf(Refusal, res);
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
		const body = shaped(Swept, res.data);
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
		const body = shaped(Swept, res.data);
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
			const body = bodyOf(
				Type.Object({ failedAreas: Type.Optional(Type.Array(Type.String())) }),
				res
			);
			expect(body?.failedAreas).toEqual(['Grant']);
		} finally {
			spy.mockRestore();
		}

		// One area failing must not abort the others: the access token is gone, and so is the client.
		expect(await adapter('AccessToken').find(at.id)).toBeUndefined();
		expect(await adapter('Client').find(clientId)).toBeUndefined();
		// And the grant survived, which is exactly what the 500 said.
		expect(await adapter('Grant').find(grantId)).toBeDefined();
	});
});
