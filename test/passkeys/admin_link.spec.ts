import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { createAdminSession } from 'lib/admin/auth/session.ts';
import { ApplicationConfig, configuration } from 'lib/configs/application.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { AccessToken } from 'lib/models/access_token.ts';
import { Client } from 'lib/models/client.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { createAdministrator } from '../administrators.ts';
import { call as tool, rpc } from '../mcp/rpc.ts';
import { codeFor } from '../two_step_page/helpers.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	Browser,
	claimsOf,
	creationOptionsIn,
	linkIn,
	mailOn,
	mailsTo,
	person,
	project,
	redeem,
	signInWithPasskey,
	type Project
} from './helpers.ts';
import { holdsCode, SECRET } from './offer_helpers.ts';

const PHISHING_RESISTANT = 'urn:example:acr:phr';

async function adminPost(
	path: string,
	cookie: string
): Promise<{ status: number; text: string; body: Record<string, unknown> }> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			headers: { cookie }
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		text,
		body: text ? (JSON.parse(text) as Record<string, unknown>) : {}
	};
}

let rpcSeq = 0;

async function mcpTokenFor(accountId: string): Promise<string> {
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId,
		scope: 'openid'
	});
	at.setAudience(MCP_RESOURCE);
	const token = await at.save();
	await rpc(
		{
			jsonrpc: '2.0',
			id: ++rpcSeq,
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
 * @proves Administrator-sent passkey enrollment links (Spec 145 US3, S14): emailed ONLY (`204 No Content`, never in
 * API/MCP/audit), refused on unverified addresses or recent email changes (< 7 days), any-browser 24-hour standalone
 * page `/account/passkey-setup` that is scanner-safe on GET, enforces TOTP when enrolled, creates a full
 * `phishing_resistant` passkey (`createdVia: 'admin_link'`), and works for both end users and colleague admins.
 */
describe('administrator-sent passkey enrollment links', () => {
	let acme: Project;
	let superAdminId: string;
	let superCookie: string;
	let colleagueId: string;
	let colleagueEmail: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		acme = await project(ACME);
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
		const superAdmin = await createAdministrator(
			'super',
			`pk-link-super-${Math.random()}@x.io`
		);
		superAdminId = superAdmin._id;
		const session = await createAdminSession({
			userId: superAdminId,
			bucketId: ADMIN_BUCKET_ID,
			signedInWith: null,
			signInAcr: configuration.acrMap.password,
			signInAmr: ['pwd'],
			signInAt: epochTime(),
			tokens: { accessToken: 'tok' }
		});
		superCookie = `${ADMIN_SESSION_COOKIE}=${session._id}`;

		colleagueEmail = `pk-link-colleague-${Math.random().toString(36).slice(2, 8)}@x.io`;
		const colleague = await createAdministrator('plain', colleagueEmail);
		colleagueId = colleague._id;
		await getUserStore(ADMIN_BUCKET_ID).update(colleagueId, { verified: true });
	});

	beforeEach(async () => {
		setSystemTime();
		resetSentEmails();
		await mailOn();
		await getBucketStore().update(acme.bucketId, { passkeyLogin: true });
		await getBucketStore().update(ADMIN_BUCKET_ID, { passkeyLogin: true });
	});

	afterEach(() => {
		setSystemTime();
	});

	it('sends an end-user setup link (204, never leaks token), enforces TOTP on /account/passkey-setup, and creates a full admin_link passkey', async () => {
		const who = await person(acme.bucketId);
		await holdsCode(acme, who.accountId);

		const res = await adminPost(
			`/admin/api/projects/${acme.bucketId}/users/${who.accountId}/passkey-link`,
			superCookie
		);
		expect(res.status).toBe(204);
		expect(res.text).toBe('');

		// Audit entry exists and contains no token/URL
		const audits = await adminAuditStore.list({
			action: 'enduser.passkey.link.send',
			targetId: who.accountId
		});
		expect(audits.entries.length).toBeGreaterThanOrEqual(1);
		expect(JSON.stringify(audits.entries[0])).not.toContain('passkey-setup');

		const mails = mailsTo(who.email);
		expect(mails.length).toBe(1);
		const setupUrl = new URL(linkIn(who.email, '/account/passkey-setup'));
		expect(setupUrl.pathname).toBe(`${acme.prefix}/account/passkey-setup`);

		// Scanner-safe GET: fetching twice in a fresh browser does NOT consume the link
		const freshBrowser = new Browser(acme.origin);
		const get1 = await freshBrowser.request(
			`${setupUrl.pathname}${setupUrl.search}`
		);
		expect(get1.status).toBe(200);
		expect(await get1.text()).toContain('authenticator app');
		const get2 = await freshBrowser.request(
			`${setupUrl.pathname}${setupUrl.search}`
		);
		expect(get2.status).toBe(200);

		const token = setupUrl.searchParams.get('token') ?? '';
		const projectParam = setupUrl.searchParams.get('project') ?? undefined;

		// Wrong TOTP refused
		const badTotp = await freshBrowser.post(setupUrl.pathname, {
			action: 'totp',
			token,
			...(projectParam ? { project: projectParam } : {}),
			code: '000000'
		});
		expect(badTotp.status).toBe(303);
		expect(badTotp.headers.get('location')).toContain('notice=code');

		// Valid TOTP passes gate
		const goodTotp = await freshBrowser.post(setupUrl.pathname, {
			action: 'totp',
			token,
			...(projectParam ? { project: projectParam } : {}),
			code: codeFor(SECRET)
		});
		expect(goodTotp.status).toBe(303);

		const createGet = await freshBrowser.request(
			goodTotp.headers.get('location') ?? ''
		);
		expect(createGet.status).toBe(200);
		const options = creationOptionsIn(await createGet.text());

		const device = new SoftAuthenticator();
		const credential = await device.create(options, { origin: acme.origin });
		const created = await freshBrowser.post(setupUrl.pathname, {
			action: 'create',
			token,
			...(projectParam ? { project: projectParam } : {}),
			credential: JSON.stringify(credential)
		});
		expect(created.status).toBe(200);
		expect(await created.text()).toContain('Passkey added');

		// Passkey stored with createdVia='admin_link' and NO recovery cap -> immediate phishing_resistant ACR
		const list = await getPasskeyStore().listOf(acme.bucketId, who.accountId);
		expect(list.length).toBe(1);
		expect(list[0]?.createdVia).toBe('admin_link');
		expect(list[0]?.recoveredUntil).toBeUndefined();

		const signedIn = await signInWithPasskey(
			new Browser(acme.origin),
			device,
			acme,
			{ acr_values: PHISHING_RESISTANT }
		);
		const tokens = await redeem(acme, signedIn.auth, signedIn.code);
		expect(claimsOf(tokens.id_token).acr).toBe(PHISHING_RESISTANT);

		// Link cannot be reused
		const reuse = await freshBrowser.request(
			`${setupUrl.pathname}${setupUrl.search}`
		);
		expect(reuse.status).toBe(400);
	});

	it('refuses unverified users and accounts whose email changed within 7 days', async () => {
		const who = await person(acme.bucketId);
		await getUserStore(acme.bucketId).update(who.accountId, {
			verified: false
		});
		const unverified = await adminPost(
			`/admin/api/projects/${acme.bucketId}/users/${who.accountId}/passkey-link`,
			superCookie
		);
		expect(unverified.status).toBe(409);

		// Email changed recently (< 7 days) refused with code: email_changed_recently
		const now = Date.now();
		await getUserStore(acme.bucketId).update(who.accountId, {
			verified: true,
			emailChangedAt: new Date(now - 2 * 24 * 60 * 60 * 1000)
		});
		const recent = await adminPost(
			`/admin/api/projects/${acme.bucketId}/users/${who.accountId}/passkey-link`,
			superCookie
		);
		expect(recent.status).toBe(409);
		expect(recent.body.code).toBe('email_changed_recently');

		// After 7 days (update emailChangedAt to 8 days ago so admin session stays live) -> allowed
		await getUserStore(acme.bucketId).update(who.accountId, {
			emailChangedAt: new Date(now - 8 * 24 * 60 * 60 * 1000)
		});
		const after7d = await adminPost(
			`/admin/api/projects/${acme.bucketId}/users/${who.accountId}/passkey-link`,
			superCookie
		);
		expect(after7d.status).toBe(204);
	});

	it('sends a colleague admin link (refuses self-send) and exposes high-consequence MCP tools', async () => {
		// Self-send refused
		const selfRes = await adminPost(
			`/admin/api/admins/${superAdminId}/passkey-link`,
			superCookie
		);
		expect(selfRes.status).toBe(409);

		// Colleague send succeeds (204)
		const res = await adminPost(
			`/admin/api/admins/${colleagueId}/passkey-link`,
			superCookie
		);
		expect(res.status).toBe(204);
		expect(res.text).toBe('');

		const audits = await adminAuditStore.list({
			action: 'admin.passkey.link.send',
			targetId: colleagueId
		});
		expect(audits.entries.length).toBeGreaterThanOrEqual(1);

		const setupUrl = new URL(linkIn(colleagueEmail, '/account/passkey-setup'));
		const colleagueProject = setupUrl.searchParams.get('project') ?? undefined;
		const browser = new Browser('http://e.ly');
		const pageRes = await browser.request(
			`${setupUrl.pathname}${setupUrl.search}`
		);
		expect(pageRes.status).toBe(200);
		const options = creationOptionsIn(await pageRes.text());
		const credential = await new SoftAuthenticator().create(options, {
			origin: 'http://e.ly'
		});
		const done = await browser.post(setupUrl.pathname, {
			action: 'create',
			token: setupUrl.searchParams.get('token') ?? '',
			...(colleagueProject ? { project: colleagueProject } : {}),
			credential: JSON.stringify(credential)
		});
		expect(done.status).toBe(200);
		expect(await done.text()).toContain('/admin');
		expect(
			(await getPasskeyStore().listOf(ADMIN_BUCKET_ID, colleagueId)).length
		).toBe(1);

		// MCP parity: project_user_passkey_link_send requires high-consequence confirmation
		const prevMcp = ApplicationConfig['mcp.enabled'];
		ApplicationConfig['mcp.enabled'] = true;
		try {
			const who = await person(acme.bucketId);
			const mcpToken = await mcpTokenFor(superAdminId);
			const first = await rpc(
				tool('project_user_passkey_link_send', {
					id: acme.bucketId,
					uid: who.accountId
				}),
				mcpToken
			);
			expect(first.result?.isError).not.toBe(true);
			const confirmation = first.result?.structuredContent?.confirmationToken;
			expect(confirmation).toBeTruthy();

			const confirmed = await rpc(
				tool('project_user_passkey_link_send', {
					id: acme.bucketId,
					uid: who.accountId,
					confirmationToken: confirmation
				}),
				mcpToken
			);
			expect(confirmed.error).toBeUndefined();
			expect(confirmed.result?.isError).not.toBe(true);
			expect(JSON.stringify(confirmed.result)).not.toContain('passkey-setup');
		} finally {
			ApplicationConfig['mcp.enabled'] = prevMcp;
		}
	});
});
