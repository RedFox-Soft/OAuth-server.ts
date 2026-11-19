import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { AccessToken } from 'lib/models/access_token.ts';
import { Client } from 'lib/models/client.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { call as tool, rpc } from '../mcp/rpc.ts';
import {
	createProject,
	freshSlug,
	idOf,
	tenant,
	withPlans,
	superAdmin
} from '../plans/admin.ts';
import { present, shaped } from '../shape.ts';
import { signInThroughPage } from '../connected_apps/helpers.ts';
import {
	ACME,
	Browser,
	mailOn,
	person,
	project,
	securityPage,
	seedPasskey,
	textOf
} from './helpers.ts';

async function request(
	method: string,
	path: string,
	cookie: string,
	body?: Readonly<Record<string, unknown>>
): Promise<{ status: number; body: Record<string, unknown> }> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { 'content-type': 'application/json', cookie },
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		body: text
			? shaped(Type.Record(Type.String(), Type.Unknown()), JSON.parse(text))
			: {}
	};
}

const Preview = Type.Object({
	confirmationRequired: Type.Literal(true),
	consequences: Type.Array(Type.String()),
	expect: Type.Record(Type.String(), Type.Number())
});

let rpcId = 0;

async function agentToken(): Promise<{ token: string; userId: string }> {
	const user = await createAdministrator(
		'super',
		`passkey-agent-${Math.random()}@x.io`
	);
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
			id: ++rpcId,
			method: 'initialize',
			params: {
				protocolVersion: '2026-07-28',
				capabilities: {},
				clientInfo: { name: 'test-agent', version: '1.0.0' }
			}
		},
		token
	);
	return { token, userId: user._id };
}

/* A project nobody configured for passkeys, as one that predates the setting is stored. */
async function plainProject(): Promise<string> {
	const bucket = await getBucketStore().create({
		name: `plain ${Math.random()}`,
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	return bucket._id;
}

/* Someone in the project whose only way in is a passkey: no password, no provider. */
async function passkeyOnlyPerson(bucketId: string): Promise<void> {
	const { accountId } = await person(bucketId);
	await getUserStore(bucketId).update(accountId, { passwordSet: false });
	await seedPasskey(bucketId, accountId);
}

/**
 * @proves A project's administrators, and their agent, turn passkeys on and off for the project: off until they do,
 * recorded in the audit trail, never on the administrators' project, free on every plan; turning it off deletes no
 * passkey, and is shown first when someone could then no longer sign in at all.
 */
describe('the project setting "Passkeys"', () => {
	let cookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		cookie = await cookieFor(await createAdministrator('super'));
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		await mailOn();
	});

	it('is off on a project that predates it', async () => {
		const id = await plainProject();

		const read = await request('GET', `/admin/api/projects/${id}`, cookie);

		expect(read.body.passkeyLogin).toBe(false);
	});

	it('is off on a project created now', async () => {
		const owner = await tenant();
		const id = idOf(
			await createProject(owner, { slug: freshSlug('passkeys') })
		);

		const read = await request(
			'GET',
			`/admin/api/projects/${id}`,
			owner.cookie
		);

		expect(read.body.passkeyLogin).toBe(false);
	});

	it('turns on at a plain http address, and the read warns that browsers need HTTPS', async () => {
		const id = await plainProject();

		const changed = await request(
			'PATCH',
			`/admin/api/projects/${id}`,
			cookie,
			{
				passkeyLogin: true
			}
		);
		const read = await request('GET', `/admin/api/projects/${id}`, cookie);

		expect(changed.status).toBe(200);
		expect({
			passkeyLogin: read.body.passkeyLogin,
			passkeysNeedHttps: read.body.passkeysNeedHttps
		}).toEqual({ passkeyLogin: true, passkeysNeedHttps: true });
	});

	it('is recorded in the audit trail naming the field', async () => {
		const id = await plainProject();

		await request('PATCH', `/admin/api/projects/${id}`, cookie, {
			passkeyLogin: true
		});

		const { entries } = await adminAuditStore.list({ targetId: id });
		expect(
			entries.some(
				(entry) =>
					entry.action === 'bucket.update' &&
					entry.attributes?.includes('passkeyLogin')
			)
		).toBe(true);
	});

	it('keeps a person’s passkeys while off, and they are back when it is on again', async () => {
		const acme = await project(ACME);
		const { email, accountId } = await person(acme.bucketId);
		await seedPasskey(acme.bucketId, accountId);
		const browser = new Browser();
		await signInThroughPage(browser, email, acme.prefix);

		await request('PATCH', `/admin/api/projects/${acme.bucketId}`, cookie, {
			passkeyLogin: false
		});
		const whileOff = textOf(
			await (await browser.request(securityPage(acme))).text()
		);
		await request('PATCH', `/admin/api/projects/${acme.bucketId}`, cookie, {
			passkeyLogin: true
		});
		const onAgain = textOf(
			await (await browser.request(securityPage(acme))).text()
		);

		expect({
			listedWhileOff: whileOff.includes('Chrome on Windows'),
			saysOff: whileOff.includes('doesn’t accept passkeys right now'),
			listedOnAgain: onAgain.includes('Chrome on Windows'),
			saysOffOnAgain: onAgain.includes('doesn’t accept passkeys right now')
		}).toEqual({
			listedWhileOff: true,
			saysOff: true,
			listedOnAgain: true,
			saysOffOnAgain: false
		});
	});

	it('turns off at once while nobody depends on a passkey alone', async () => {
		const id = await plainProject();
		await getBucketStore().update(id, { passkeyLogin: true });
		const { accountId } = await person(id);
		await seedPasskey(id, accountId);

		const changed = await request(
			'PATCH',
			`/admin/api/projects/${id}`,
			cookie,
			{
				passkeyLogin: false
			}
		);

		expect(changed.status).toBe(200);
		expect((await getBucketStore().find(id))?.passkeyLogin).toBe(false);
	});

	it('shows how many people could no longer sign in before turning off, and changes nothing yet', async () => {
		const id = await plainProject();
		await getBucketStore().update(id, { passkeyLogin: true });
		await passkeyOnlyPerson(id);

		const asked = await request('PATCH', `/admin/api/projects/${id}`, cookie, {
			passkeyLogin: false
		});

		expect(asked.status).toBe(409);
		const preview = shaped(Preview, asked.body);
		expect(preview.expect).toEqual({ passkeyOnly: 1 });
		expect(preview.consequences).toContain(
			'1 person can only sign in with a passkey; they will not be able to sign in.'
		);
		expect((await getBucketStore().find(id))?.passkeyLogin).toBe(true);
	});

	it('counts only passkeys that sign in here when showing who could no longer sign in', async () => {
		const id = await plainProject();
		await getBucketStore().update(id, { passkeyLogin: true });
		await passkeyOnlyPerson(id);
		for (const fields of [
			{ rpId: 'old.example.test' },
			{ copiedAt: new Date() }
		]) {
			const { accountId } = await person(id);
			await getUserStore(id).update(accountId, { passwordSet: false });
			await seedPasskey(id, accountId, fields);
		}

		const asked = await request('PATCH', `/admin/api/projects/${id}`, cookie, {
			passkeyLogin: false
		});

		expect(asked.status).toBe(409);
		expect(shaped(Preview, asked.body).expect).toEqual({ passkeyOnly: 1 });
	});

	it('turns off once confirmed with the counts it showed', async () => {
		const id = await plainProject();
		await getBucketStore().update(id, { passkeyLogin: true });
		await passkeyOnlyPerson(id);

		const confirmed = await request(
			'PATCH',
			`/admin/api/projects/${id}`,
			cookie,
			{ passkeyLogin: false, confirm: true, expect: { passkeyOnly: 1 } }
		);

		expect(confirmed.status).toBe(200);
		expect((await getBucketStore().find(id))?.passkeyLogin).toBe(false);
	});

	it('is set by an agent through project_update, attributed to it', async () => {
		const id = await plainProject();
		const { token, userId } = await agentToken();

		const response = await rpc(
			tool('project_update', { id, passkeyLogin: true }),
			token
		);

		expect(response.result?.isError).not.toBe(true);
		expect((await getBucketStore().find(id))?.passkeyLogin).toBe(true);
		const { entries } = await adminAuditStore.list({
			action: 'bucket.update',
			targetId: id
		});
		expect(
			entries.find((entry) => entry.actorId === userId)?.attributes
		).toContain('passkeyLogin');
	});

	it('is shown to an agent first when turning it off would leave someone without a way in', async () => {
		const id = await plainProject();
		await getBucketStore().update(id, { passkeyLogin: true });
		await passkeyOnlyPerson(id);
		const { token } = await agentToken();

		const response = await rpc(
			tool('project_update', { id, passkeyLogin: false }),
			token
		);

		expect(response.result?.isError).toBe(true);
		expect(JSON.stringify(response.result?.structuredContent ?? {})).toContain(
			'passkeyOnly'
		);
		expect((await getBucketStore().find(id))?.passkeyLogin).toBe(true);
	});

	it('is told to an agent that a passkey meets every requirement of a code', async () => {
		const { token } = await agentToken();

		const listed = await rpc(
			{ jsonrpc: '2.0', id: ++rpcId, method: 'tools/list', params: {} },
			token
		);

		const tools = present(listed.result?.tools, 'the tool list');
		const asking = tools.filter((entry) =>
			/requireCode|withCode/.test(entry.description ?? '')
		);
		expect(asking.length).toBeGreaterThan(0);
		for (const entry of asking) {
			expect({
				tool: entry.name,
				passkey: /passkey/.test(entry.description ?? '')
			}).toEqual({
				tool: entry.name,
				passkey: true
			});
		}
	});

	it('is free on every plan', async () => {
		const operator = await superAdmin();
		await withPlans(operator, true);
		try {
			const owner = await tenant();
			const id = idOf(await createProject(owner));

			const changed = await request(
				'PATCH',
				`/admin/api/projects/${id}`,
				owner.cookie,
				{ passkeyLogin: true }
			);

			expect(changed.status).toBe(200);
		} finally {
			await withPlans(operator, false);
		}
	});

	it('is refused on the administrators’ project, naming the field', async () => {
		const refused = await request(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			cookie,
			{ passkeyLogin: true }
		);

		expect(refused.status).toBe(422);
		expect(refused.body.field).toBe('passkeyLogin');
	});
});
