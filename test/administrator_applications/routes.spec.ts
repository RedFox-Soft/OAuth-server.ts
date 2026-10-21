import { describe, it, expect, beforeAll, beforeEach, spyOn } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.js';
import { adapter, adminAuditStore } from 'lib/adapters/index.js';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID,
	ADMIN_SESSION_COOKIE
} from 'lib/admin/consts.ts';
import { ISSUER } from 'lib/configs/env.js';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';
import * as plans from 'lib/plans/enforce.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';

const BASE = '/admin/api/administrators/applications';

async function cookieFor(kind: AdminKind) {
	const user = await createAdministrator(kind);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

async function call(
	cookie: string,
	method: string,
	path: string,
	body?: unknown
) {
	const res = await elysia.handle(
		new Request(`${ISSUER}${path}`, {
			method,
			headers: {
				cookie,
				origin: ISSUER,
				...(body === undefined ? {} : { 'content-type': 'application/json' })
			},
			body: body === undefined ? undefined : JSON.stringify(body)
		})
	);
	const text = await res.text();
	return {
		status: res.status,
		body: (text ? JSON.parse(text) : null) as Record<string, unknown>
	};
}

const OPS = {
	clientName: 'Ops tool',
	redirectUris: ['https://ops.example/cb'],
	postLogoutRedirectUris: ['https://ops.example/']
};

/**
 * @proves Only a super administrator manages the applications of the Administrators project, and can register
 * one for an internal tool: sign-in only, confidential, recorded before each change, with the console's and the
 * agent's own clients out of reach.
 */
describe('the administrators’ applications API', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('registers an application whose secret is shown once and whose issuer is the root', async () => {
		const cookie = await cookieFor('super');

		const created = await call(cookie, 'POST', BASE, OPS);

		expect(created.status).toBe(201);
		expect(created.body).toMatchObject({
			clientName: 'Ops tool',
			issuer: ISSUER,
			refreshTokens: true,
			tokenEndpointAuthMethod: 'client_secret_basic'
		});
		expect(created.body.secret).toBeString();
		const read = await call(
			cookie,
			'GET',
			`${BASE}/${String(created.body.clientId)}`
		);
		expect(read.status).toBe(200);
		expect(read.body.secret).toBeUndefined();
		const stored = await adapter('Client').find(String(created.body.clientId));
		expect(stored).toMatchObject({
			bucketId: ADMIN_BUCKET_ID,
			grantTypes: ['authorization_code', 'refresh_token'],
			responseTypes: ['code']
		});
	});

	it('changes, rotates and deletes it', async () => {
		const cookie = await cookieFor('super');
		const { body } = await call(cookie, 'POST', BASE, OPS);
		const path = `${BASE}/${String(body.clientId)}`;

		const changed = await call(cookie, 'PATCH', path, {
			clientName: 'Ops',
			refreshTokens: false
		});
		expect(changed.status).toBe(200);
		expect(changed.body).toMatchObject({
			clientName: 'Ops',
			refreshTokens: false
		});
		expect(await adapter('Client').find(String(body.clientId))).toMatchObject({
			grantTypes: ['authorization_code']
		});

		const rotated = await call(cookie, 'POST', `${path}/secret`);
		expect(rotated.status).toBe(200);
		expect(rotated.body.secret).toBeString();
		expect(rotated.body.secret).not.toBe(body.secret);

		expect((await call(cookie, 'DELETE', path)).status).toBe(200);
		expect((await call(cookie, 'GET', path)).status).toBe(404);
	});

	it('lists the registered applications and never the console’s or the agent’s client', async () => {
		const cookie = await cookieFor('super');
		await call(cookie, 'POST', BASE, OPS);

		const listed = await call(cookie, 'GET', BASE);

		const ids = (listed.body.applications as { clientId: string }[]).map(
			(a) => a.clientId
		);
		expect(ids.length).toBeGreaterThan(0);
		expect(ids).not.toContain(ADMIN_CLIENT_ID);
		expect(ids).not.toContain(ADMIN_MCP_CLIENT_ID);
	});

	it('answers the console’s and the agent’s client as unknown', async () => {
		const cookie = await cookieFor('super');

		for (const id of [ADMIN_CLIENT_ID, ADMIN_MCP_CLIENT_ID]) {
			expect((await call(cookie, 'GET', `${BASE}/${id}`)).status).toBe(404);
			expect(
				(await call(cookie, 'PATCH', `${BASE}/${id}`, { clientName: 'x' }))
					.status
			).toBe(404);
			expect((await call(cookie, 'POST', `${BASE}/${id}/secret`)).status).toBe(
				404
			);
			expect((await call(cookie, 'DELETE', `${BASE}/${id}`)).status).toBe(404);
		}
	});

	it('refuses an administrator who is not a super administrator', async () => {
		const owner = await cookieFor('super');
		const { body } = await call(owner, 'POST', BASE, OPS);
		const path = `${BASE}/${String(body.clientId)}`;
		const plain = await cookieFor('plain');

		expect((await call(plain, 'GET', BASE)).status).toBe(403);
		expect((await call(plain, 'POST', BASE, OPS)).status).toBe(403);
		expect((await call(plain, 'GET', path)).status).toBe(403);
		expect((await call(plain, 'PATCH', path, { clientName: 'x' })).status).toBe(
			403
		);
		expect((await call(plain, 'POST', `${path}/secret`)).status).toBe(403);
		expect((await call(plain, 'DELETE', path)).status).toBe(403);
	});

	it('refuses an application that does not authenticate', async () => {
		const cookie = await cookieFor('super');

		const res = await call(cookie, 'POST', BASE, {
			...OPS,
			tokenEndpointAuthMethod: 'none'
		});

		expect(res.status).toBe(422);
	});

	it('refuses a body that names a grant, a response type, a resource or a project', async () => {
		const cookie = await cookieFor('super');

		for (const extra of [
			{ grantTypes: ['client_credentials'] },
			{ responseTypes: ['code token'] },
			{ resource: 'https://api.root.example/' },
			{ projectId: 'redfox' }
		]) {
			expect(
				(await call(cookie, 'POST', BASE, { ...OPS, ...extra })).status
			).toBe(422);
		}
	});

	it('records the change before making it', async () => {
		const cookie = await cookieFor('super');
		let existedWhenRecorded: boolean | undefined;
		const record = adminAuditStore.record.bind(adminAuditStore);
		spyOn(adminAuditStore, 'record').mockImplementation(async (entry) => {
			if (entry.action === 'admin.application.create') {
				existedWhenRecorded = Boolean(
					await adapter('Client').find(entry.targetId)
				);
			}
			return record(entry);
		});

		const created = await call(cookie, 'POST', BASE, OPS);

		expect(created.status).toBe(201);
		expect(existedWhenRecorded).toBe(false);
	});

	it('never consults a plan', async () => {
		const cookie = await cookieFor('super');
		const room = spyOn(plans, 'assertApplicationRoom');

		await call(cookie, 'POST', BASE, OPS);

		expect(room).not.toHaveBeenCalled();
	});

	it('leaves the project application routes closed to the administrators’ project', async () => {
		const cookie = await cookieFor('super');

		const res = await call(
			cookie,
			'POST',
			`/admin/api/projects/${ADMIN_BUCKET_ID}/clients`,
			{
				grantTypes: ['authorization_code'],
				redirectUris: ['https://ops.example/cb'],
				tokenEndpointAuthMethod: 'client_secret_basic'
			}
		);

		expect(res.status).toBe(403);
	});
});
