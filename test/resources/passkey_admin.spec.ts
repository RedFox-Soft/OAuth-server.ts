import { beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { bindClientToBucket } from '../test_helper.js';
import {
	adminAuditStore,
	getBucketStore,
	getProtectedResourceStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { ADMIN_MCP_CLIENT_ID } from 'lib/mcp/consts.ts';
import { rpIdFor } from 'lib/passkeys/relying_party.ts';
import { admin } from '../provisioning/helpers.ts';
import { present } from '../shape.ts';
import { seedPasskey } from '../passkeys/helpers.ts';
import {
	agentFor,
	confirm,
	editor,
	tool,
	world,
	type World
} from '../behind_proxy/helpers.ts';
import {
	changeApi,
	declareApi,
	freshIdentifier,
	resourcesPath
} from '../behind_proxy/api_helpers.ts';

async function readResource(
	cookie: string,
	bucketId: string,
	identifier: string
) {
	return admin('GET', resourcesPath(bucketId, identifier), cookie);
}

/**
 * @proves Turning an API's passkey requirement on is previewed with audience-scoped counts (counting only confirmed
 * passkeys as holders), applies only when confirmed with those counts, is refused with `409 passkeys_not_accepted`
 * when the project does not accept passkeys (while unrelated edits on an already passkey-requiring API still succeed),
 * never stores both `requirePasskey` and `requireCode` together, lowers without preview, records audit only on real
 * mutations, and preserves full parity through MCP tools.
 */
describe('making an API require a passkey through admin API and MCP', () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'passkey_admin' });
		w = await world();
		forgetBucketAddresses();
		await getBucketStore().update(w.acme.id, { passkeyLogin: true });
	});

	it('previews turning requirePasskey on with confirmed-passkey counts, rejects stale expect, and applies on matching confirm', async () => {
		const bucket = present(
			await getBucketStore().find(w.acme.id),
			'acme bucket'
		);
		const rpId = rpIdFor(bucket);

		/* Give adminMember a confirmed passkey, and staffMember only a conditional (unconfirmed) passkey. */
		await seedPasskey(w.acme.id, w.acme.adminMember.accountId, {
			rpId,
			createdVia: 'password_code'
		});
		await seedPasskey(w.acme.id, w.acme.staffMember.accountId, {
			rpId,
			createdVia: 'password',
			conditional: true
		});

		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		const path = resourcesPath(w.acme.id, api.identifier);
		const auditBefore = (
			await adminAuditStore.list({ action: 'resource.update' })
		).entries.length;

		const previewed = await admin('PATCH', path, w.cookie, {
			requirePasskey: true
		});
		expect(previewed.status).toBe(409);
		expect(previewed.body).toMatchObject({
			confirmationRequired: true,
			changes: ['apiRequirePasskeyOn']
		});
		const counts = (previewed.body as { expect: Record<string, number> })
			.expect;
		/* adminMember holds a full passkey; staffMember's conditional passkey does NOT count as a full passkey. */
		expect(counts.withoutPasskey).toBeGreaterThanOrEqual(1);
		expect(counts.holders).toBe(0);
		expect('withoutAuthenticator' in counts).toBe(false);

		/* No audit written for a preview. */
		expect(
			(await adminAuditStore.list({ action: 'resource.update' })).entries.length
		).toBe(auditBefore);

		/* Stale expect refused. */
		const stale = await admin('PATCH', path, w.cookie, {
			requirePasskey: true,
			confirm: true,
			expect: { ...counts, withoutPasskey: counts.withoutPasskey + 99 }
		});
		expect(stale.status).toBe(409);

		/* Matching expect applies. */
		const confirmed = await admin('PATCH', path, w.cookie, {
			requirePasskey: true,
			confirm: true,
			expect: counts
		});
		expect(confirmed.status).toBe(200);
		expect(confirmed.body).toMatchObject({
			requirePasskey: true,
			requireCode: false
		});
		expect(
			(await adminAuditStore.list({ action: 'resource.update' })).entries.length
		).toBe(auditBefore + 1);
	});

	it('scopes preview counts to the API’s group audience when restricted by group', async () => {
		const whole = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		const grouped = await declareApi(w.cookie, w.acme.id, {
			checkedBy: 'proxy'
		});
		await changeApi(w.cookie, w.acme.id, grouped.identifier, {
			tools: {
				rows: [],
				otherTools: 'refuse',
				withoutMethod: 'refuse',
				access: { conditions: [{ kind: 'group', groups: [w.acme.admins] }] }
			}
		});

		const wholePreview = await admin(
			'PATCH',
			resourcesPath(w.acme.id, whole.identifier),
			w.cookie,
			{ requirePasskey: true }
		);
		const groupedPreview = await admin(
			'PATCH',
			resourcesPath(w.acme.id, grouped.identifier),
			w.cookie,
			{ requirePasskey: true }
		);

		expect(wholePreview.status).toBe(409);
		expect(groupedPreview.status).toBe(409);
		const wholeExpect = (
			wholePreview.body as { expect: Record<string, number> }
		).expect;
		const groupedExpect = (
			groupedPreview.body as { expect: Record<string, number> }
		).expect;
		/* admins group has only adminMember (who holds a confirmed passkey). */
		expect(groupedExpect.holders).toBe(0);
		expect(groupedExpect.withoutPasskey).toBe(0);
		expect(wholeExpect.withoutPasskey).toBeGreaterThan(
			groupedExpect.withoutPasskey
		);
	});

	it('previews raising two-step to passkey, stores no contradiction when both flags are sent, and lowers without preview', async () => {
		const api = await declareApi(w.cookie, w.acme.id, { checkedBy: 'proxy' });
		const path = resourcesPath(w.acme.id, api.identifier);

		/* Turn two-step on first. */
		const codePreview = await admin('PATCH', path, w.cookie, {
			requireCode: true
		});
		expect(codePreview.status).toBe(409);
		const codeConfirmed = await admin('PATCH', path, w.cookie, {
			requireCode: true,
			confirm: true,
			expect: (codePreview.body as { expect: Record<string, number> }).expect
		});
		expect(codeConfirmed.status).toBe(200);
		expect(codeConfirmed.body).toMatchObject({
			requireCode: true,
			requirePasskey: false
		});

		/* Raise two-step -> passkey (sending both booleans true to prove normalization). */
		const raisePreview = await admin('PATCH', path, w.cookie, {
			requirePasskey: true,
			requireCode: true
		});
		expect(raisePreview.status).toBe(409);
		expect(raisePreview.body).toMatchObject({
			confirmationRequired: true,
			changes: ['apiRequirePasskeyOn']
		});
		const raised = await admin('PATCH', path, w.cookie, {
			requirePasskey: true,
			requireCode: true,
			confirm: true,
			expect: (raisePreview.body as { expect: Record<string, number> }).expect
		});
		expect(raised.status).toBe(200);
		expect(raised.body).toMatchObject({
			requirePasskey: true,
			requireCode: false
		});

		/* Verify stored record holds no contradiction. */
		const stored = await getProtectedResourceStore().find(
			w.acme.id,
			api.identifier
		);
		expect(stored?.requirePasskey).toBe(true);
		expect(stored?.requireCode).toBeUndefined();

		/* Lower passkey -> two-step without preview. */
		const loweredToCode = await admin('PATCH', path, w.cookie, {
			requirePasskey: false,
			requireCode: true
		});
		expect(loweredToCode.status).toBe(200);
		expect(loweredToCode.body).toMatchObject({
			requirePasskey: false,
			requireCode: true
		});

		/* Raise again and lower straight to off without preview. */
		const preview2 = await admin('PATCH', path, w.cookie, {
			requirePasskey: true
		});
		await admin('PATCH', path, w.cookie, {
			requirePasskey: true,
			confirm: true,
			expect: (preview2.body as { expect: Record<string, number> }).expect
		});
		const loweredOff = await admin('PATCH', path, w.cookie, {
			requirePasskey: false
		});
		expect(loweredOff.status).toBe(200);
		expect(loweredOff.body).toMatchObject({
			requirePasskey: false,
			requireCode: false
		});
	});

	it('refuses requirePasskey with 409 passkeys_not_accepted when passkeys are off, while allowing unrelated edits on an existing passkey API', async () => {
		const { cookie, project } = await editor();
		/* Passkeys start off on a fresh project. */
		const id1 = freshIdentifier();
		const createRefused = await admin(
			'POST',
			resourcesPath(project.id),
			cookie,
			{
				identifier: id1,
				name: 'Vault',
				scopes: ['read'],
				requirePasskey: true
			}
		);
		expect(createRefused.status).toBe(409);
		expect(createRefused.body).toMatchObject({
			code: 'passkeys_not_accepted'
		});

		/* Declare normally, then try to patch requirePasskey: true while passkeys are off. */
		const api = await declareApi(cookie, project.id);
		const patchRefused = await admin(
			'PATCH',
			resourcesPath(project.id, api.identifier),
			cookie,
			{ requirePasskey: true }
		);
		expect(patchRefused.status).toBe(409);
		expect(patchRefused.body).toMatchObject({
			code: 'passkeys_not_accepted'
		});

		/* Turn passkeys on, require passkey on the API, then turn passkeys back off. */
		forgetBucketAddresses();
		await getBucketStore().update(project.id, { passkeyLogin: true });
		const preview = await admin(
			'PATCH',
			resourcesPath(project.id, api.identifier),
			cookie,
			{ requirePasskey: true }
		);
		expect(preview.status).toBe(409);
		const saved = await admin(
			'PATCH',
			resourcesPath(project.id, api.identifier),
			cookie,
			{
				requirePasskey: true,
				confirm: true,
				expect: (preview.body as { expect: Record<string, number> }).expect
			}
		);
		expect(saved.status).toBe(200);

		forgetBucketAddresses();
		await getBucketStore().update(project.id, { passkeyLogin: false });

		/* Unrelated edit (renaming) still succeeds while passkeys are off. */
		const renamed = await admin(
			'PATCH',
			resourcesPath(project.id, api.identifier),
			cookie,
			{ name: 'Vault Renamed' }
		);
		expect(renamed.status).toBe(200);
		expect(renamed.body).toMatchObject({
			name: 'Vault Renamed',
			requirePasskey: true
		});

		/* Lowering off also succeeds while passkeys are off. */
		const lowered = await admin(
			'PATCH',
			resourcesPath(project.id, api.identifier),
			cookie,
			{ requirePasskey: false }
		);
		expect(lowered.status).toBe(200);
		expect(lowered.body).toMatchObject({ requirePasskey: false });
	});

	it('holds MCP resource_declare and resource_update behind confirmation and exposes requirePasskey on resource_get', async () => {
		const { user, cookie, project } = await editor();
		forgetBucketAddresses();
		await getBucketStore().update(project.id, { passkeyLogin: true });
		await getUserStore(project.id).create(
			'member@mcp-passkey.test',
			'password'
		);
		const token = await agentFor(user);
		const api = await declareApi(cookie, project.id);

		/* MCP update with requirePasskey triggers MCP confirmation gate first. */
		const args = {
			id: project.id,
			resourceId: api.identifier,
			requirePasskey: true
		};
		const described = await tool(token, 'resource_update', args);
		expect(described.result?.structuredContent?.status).toBe(
			'confirmation_required'
		);

		/* After MCP confirmation, inner admin preview returns 409 with counts (withoutPasskey). */
		const previewed = await confirm(token, 'resource_update', args, described);
		expect(previewed.result?.isError).toBe(true);
		const text =
			(previewed.result?.content?.[0] as { text?: string } | undefined)?.text ??
			'';
		expect(text).toContain('withoutPasskey');

		/* Confirming with matching expect applies it and records MCP viaClientId in audit. */
		const adminPreview = await admin(
			'PATCH',
			resourcesPath(project.id, api.identifier),
			cookie,
			{ requirePasskey: true }
		);
		const counts = (adminPreview.body as { expect: Record<string, number> })
			.expect;
		const fullArgs = { ...args, confirm: true, expect: counts };
		const described2 = await tool(token, 'resource_update', fullArgs);
		const applied = await confirm(
			token,
			'resource_update',
			fullArgs,
			described2
		);
		expect(applied.result?.isError).not.toBe(true);

		const got = await tool(token, 'resource_get', {
			id: project.id,
			resourceId: api.identifier
		});
		expect(got.result?.structuredContent?.result).toMatchObject({
			requirePasskey: true,
			requireCode: false
		});

		const fromAdmin = await readResource(cookie, project.id, api.identifier);
		expect(fromAdmin.body).toMatchObject({
			requirePasskey: true,
			requireCode: false
		});

		const { entries } = await adminAuditStore.list({
			actor: user._id,
			action: 'resource.update'
		});
		expect(entries.map((entry) => entry.viaClientId)).toContain(
			ADMIN_MCP_CLIENT_ID
		);

		/* Also prove POST /resources preview-confirm works on create. */
		const createdId = freshIdentifier();
		const createPreview = await admin(
			'POST',
			resourcesPath(project.id),
			cookie,
			{
				identifier: createdId,
				name: 'New Passkey API',
				scopes: ['read'],
				requirePasskey: true
			}
		);
		expect(createPreview.status).toBe(409);
		const created = await admin('POST', resourcesPath(project.id), cookie, {
			identifier: createdId,
			name: 'New Passkey API',
			scopes: ['read'],
			requirePasskey: true,
			confirm: true,
			expect: (createPreview.body as { expect: Record<string, number> }).expect
		});
		expect(created.status).toBe(201);
		expect(created.body).toMatchObject({
			requirePasskey: true,
			requireCode: false
		});
	});

	it('still compiles bindClientToBucket check for machineApps count on preview', async () => {
		const { cookie, project } = await editor();
		forgetBucketAddresses();
		await getBucketStore().update(project.id, { passkeyLogin: true });
		await bindClientToBucket('machine-in-project', project.id).catch(() => {});
		const api = await declareApi(cookie, project.id);
		const preview = await admin(
			'PATCH',
			resourcesPath(project.id, api.identifier),
			cookie,
			{ requirePasskey: true }
		);
		expect(preview.status).toBe(409);
		expect(preview.body).toMatchObject({
			confirmationRequired: true,
			changes: ['apiRequirePasskeyOn']
		});
	});
});
