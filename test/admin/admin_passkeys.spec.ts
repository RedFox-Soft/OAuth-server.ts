import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adapter,
	adminAuditStore,
	adminSessionStore,
	getBucketStore,
	getPasskeyStore,
	getPersonActivityStore,
	getUserStore
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID,
	ADMIN_SESSION_COOKIE
} from 'lib/admin/consts.ts';
import { createAdminSession } from 'lib/admin/auth/session.ts';
import { ApplicationConfig, configuration } from 'lib/configs/application.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { adminConsoleClientSeed } from 'lib/consts/admin_seed.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { AccessToken } from 'lib/models/access_token.ts';
import { Client } from 'lib/models/client.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { mayCreateAfterSignIn, offerable } from 'lib/passkeys/offerable.ts';
import { rpIdFor } from 'lib/passkeys/relying_party.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import { sentEmails } from 'lib/mail/mailer.ts';
import { createAdministrator } from '../administrators.ts';
import { call as tool, rpc } from '../mcp/rpc.ts';
import { present, shaped } from '../shape.ts';
import { SoftAuthenticator } from '../passkeys/authenticator.ts';
import {
	Browser,
	codeAfter,
	mailOn,
	postPasskey,
	signInPage,
	type Project
} from '../passkeys/helpers.ts';

async function adminRequest(
	method: string,
	path: string,
	cookie: string,
	body?: unknown
): Promise<{
	status: number;
	body: Record<string, unknown>;
	response: Response;
}> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: {
				...(body === undefined ? {} : { 'content-type': 'application/json' }),
				cookie
			},
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	let parsed: Record<string, unknown> = {};
	try {
		if (text) parsed = JSON.parse(text) as Record<string, unknown>;
	} catch {
		parsed = { raw: text };
	}
	return { status: response.status, body: parsed, response };
}

async function sessionCookieFor(
	userId: string,
	signIn: {
		signInAcr?: string | null;
		signInAmr?: string[];
		signInAt?: number;
	} = {}
): Promise<{ cookie: string; sessionId: string }> {
	const session = await createAdminSession({
		userId,
		bucketId: ADMIN_BUCKET_ID,
		signedInWith: null,
		signInAcr: signIn.signInAcr ?? configuration.acrMap.password,
		signInAmr: signIn.signInAmr ?? ['pwd'],
		signInAt: signIn.signInAt ?? epochTime(),
		tokens: { accessToken: 'test-token' }
	});
	return {
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`,
		sessionId: session._id
	};
}

let rpcSeq = 0;

async function mcpTokenFor(
	accountId: string,
	signInAcr: string = configuration.acrMap.password
): Promise<string> {
	const at = new AccessToken({
		client: await Client.find(ADMIN_MCP_CLIENT_ID),
		accountId,
		scope: 'openid',
		acr: signInAcr,
		signInAcr
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
				clientInfo: { name: 'admin-passkeys-test', version: '1.0.0' }
			}
		},
		token
	);
	return token;
}

const OptionsShape = Type.Object({
	options: Type.Record(Type.String(), Type.Unknown())
});

const PasskeyRespShape = Type.Object({
	passkey: Type.Object({
		id: Type.String(),
		name: Type.Optional(Type.String()),
		state: Type.String(),
		createdVia: Type.String(),
		confirmed: Type.Boolean()
	})
});

function linkMatching(
	sent: { text: string; html: string }[],
	pattern: RegExp
): string {
	for (let i = sent.length - 1; i >= 0; i -= 1) {
		const m = sent[i].text.match(pattern) ?? sent[i].html.match(pattern);
		if (m) return m[0];
	}
	throw new Error(`expected email link matching ${String(pattern)}`);
}

/**
 * @proves Super administrators enable passkeys on the Administrators project; any administrator registers, renames,
 * removes, disowns, and signs in with their own passkey from the console header (with strong-sign-in or fresh
 * password + session-bound email link, never conditional and never offered after password); and super administrators
 * list and revoke colleagues' passkeys via both console and MCP with full secrecy, audit, and sign-out cascades.
 */
describe('administrators passkeys (personal management, sign-in, disown, and super-admin revocation)', () => {
	const sent = sentEmails;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		await adapter('Client').upsert(
			ADMIN_CLIENT_ID,
			adminConsoleClientSeed(ISSUER)
		);
	});

	beforeEach(async () => {
		ApplicationConfig['mcp.enabled'] = true;
		sentEmails.length = 0;
		await mailOn();
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			passkeyLogin: true,
			consolePasskeyRequired: false,
			passwordLogin: true,
			totpRequired: false
		});
	});

	it('enables passkeys on Administrators, reports passkeyHolders in summary, and keeps passkeyOffer disabled', async () => {
		const superAdmin = await createAdministrator('super');
		const { cookie } = await sessionCookieFor(superAdmin._id);

		const offerRefused = await adminRequest(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			cookie,
			{ passkeyOffer: true }
		);
		expect(offerRefused.status).toBe(422);
		expect(offerRefused.body.field).toBe('passkeyOffer');

		const summary = await adminRequest(
			'GET',
			`/admin/api/projects/${ADMIN_BUCKET_ID}/summary`,
			cookie
		);
		expect(summary.status).toBe(200);
		expect(typeof summary.body.passkeyHolders).toBe('number');

		const bucket = present(
			await getBucketStore().find(ADMIN_BUCKET_ID),
			'admin bucket'
		);
		await getUserStore(ADMIN_BUCKET_ID).update(superAdmin._id, {
			verified: true
		});
		const verifiedUser = present(
			await getUserStore(ADMIN_BUCKET_ID).find(superAdmin._id),
			'super admin'
		);
		expect(await offerable(bucket, verifiedUser)).toBe(false);
		expect(await mayCreateAfterSignIn(bucket, verifiedUser)).toBe(false);
	});

	it('lets an administrator add a passkey via fresh password + session-bound email link, rename it, and remove it', async () => {
		const admin = await createAdministrator('plain');
		await getUserStore(ADMIN_BUCKET_ID).update(admin._id, { verified: true });
		const { cookie, sessionId } = await sessionCookieFor(admin._id, {
			signInAcr: configuration.acrMap.password,
			signInAmr: ['pwd'],
			signInAt: epochTime()
		});

		/* Direct add options refused before email confirmation on a password-only sign-in. */
		const blockedOpts = await adminRequest(
			'POST',
			'/admin/api/me/passkeys/add/options',
			cookie
		);
		expect(blockedOpts.status).toBe(409);

		/* Request email confirmation link. */
		const linkResp = await adminRequest(
			'POST',
			'/admin/api/me/passkeys/add-link',
			cookie
		);
		expect(linkResp.status).toBe(200);
		const confirmUrl = linkMatching(
			sent,
			/https?:\/\/[^\s"'<>]+\/admin\/me\/passkeys\/confirm\?token=[^\s"'<>]+/
		);

		/* A mail scanner without the session cookie must NOT consume the link. */
		const scannerRes = await elysia.handle(new Request(confirmUrl));
		expect(scannerRes.status).toBe(302);
		expect(scannerRes.headers.get('location')).toContain('linkError=expired');

		/* Opening the link in the same browser session prepares the add ceremony. */
		const confirmedRes = await elysia.handle(
			new Request(confirmUrl, { headers: { cookie } })
		);
		expect(confirmedRes.status).toBe(302);
		expect(confirmedRes.headers.get('location')).toContain('confirmed=add');

		/* Fetch WebAuthn registration options and complete with SoftAuthenticator. */
		const optsRes = await adminRequest(
			'POST',
			'/admin/api/me/passkeys/add/options',
			cookie
		);
		expect(optsRes.status).toBe(200);
		const options = shaped(OptionsShape, optsRes.body)
			.options as unknown as PublicKeyCredentialCreationOptionsJSON;
		const auth = new SoftAuthenticator();
		const createdCred = await auth.create(options, { origin: 'http://e.ly' });

		const addedRes = await adminRequest(
			'POST',
			'/admin/api/me/passkeys/add',
			cookie,
			{ credential: JSON.stringify(createdCred), name: 'Work Laptop' }
		);
		expect(addedRes.status).toBe(201);
		const added = shaped(PasskeyRespShape, addedRes.body).passkey;
		expect(added.name).toBe('Work Laptop');
		expect(added.createdVia).toBe('password_mail');
		expect(added.confirmed).toBe(true);

		/* Adding a passkey MUST NOT upgrade the console session's signInAcr. */
		const sessionAfter = await adminSessionStore.find(sessionId);
		expect(sessionAfter?.signInAcr).toBe(configuration.acrMap.password);

		/* Audit entry recorded and "added" email carries &project=admin disown link. */
		const { entries: addAudit } = await adminAuditStore.list({
			targetId: admin._id
		});
		expect(addAudit.some((e) => e.action === 'admin.passkey.add')).toBe(true);
		const disownLink = linkMatching(
			sent,
			/https?:\/\/[^\s"'<>]+\/account\/security\/passkey-disown\?token=[^\s"'<>]+&project=admin/
		);
		expect(disownLink).toContain('project=admin');

		/* Rename passkey (no audit entry, no email). */
		const mailsBeforeRename = sent.length;
		const renamed = await adminRequest(
			'PATCH',
			`/admin/api/me/passkeys/${added.id}`,
			cookie,
			{ name: 'Primary Key' }
		);
		expect(renamed.status).toBe(200);
		expect(shaped(PasskeyRespShape, renamed.body).passkey.name).toBe(
			'Primary Key'
		);
		expect(sent.length).toBe(mailsBeforeRename);

		/* Remove passkey after strong sign-in. */
		const strong = await sessionCookieFor(admin._id, {
			signInAcr: configuration.acrMap.phishing_resistant,
			signInAmr: ['pop', 'user', 'mfa'],
			signInAt: epochTime()
		});
		const removed = await adminRequest(
			'DELETE',
			`/admin/api/me/passkeys/${added.id}`,
			strong.cookie
		);
		expect(removed.status).toBe(200);
		expect(await getPasskeyStore().countOf(ADMIN_BUCKET_ID, admin._id)).toBe(0);
		const { entries: removeAudit } = await adminAuditStore.list({
			targetId: admin._id
		});
		expect(removeAudit.some((e) => e.action === 'admin.passkey.remove')).toBe(
			true
		);
	});

	it('signs an administrator in with a passkey on Administrators, satisfies totpRequired without a code, and never sends signalUnknownCredential', async () => {
		await getBucketStore().update(ADMIN_BUCKET_ID, {
			passkeyLogin: true,
			totpRequired: true
		});
		const admin = await createAdministrator('plain');
		await getUserStore(ADMIN_BUCKET_ID).update(admin._id, { verified: true });
		const { cookie } = await sessionCookieFor(admin._id, {
			signInAcr: configuration.acrMap.multi_factor,
			signInAmr: ['pwd', 'otp', 'mfa'],
			signInAt: epochTime()
		});

		const optsRes = await adminRequest(
			'POST',
			'/admin/api/me/passkeys/add/options',
			cookie
		);
		const options = shaped(OptionsShape, optsRes.body)
			.options as unknown as PublicKeyCredentialCreationOptionsJSON;
		const auth = new SoftAuthenticator();
		const createdCred = await auth.create(options, { origin: 'http://e.ly' });
		const addedRes = await adminRequest(
			'POST',
			'/admin/api/me/passkeys/add',
			cookie,
			{ credential: JSON.stringify(createdCred) }
		);
		expect(addedRes.status).toBe(201);

		/* Sign in to the console client via the Administrators sign-in page with the passkey. */
		const adminProject: Project = {
			bucketId: ADMIN_BUCKET_ID,
			clientId: ADMIN_CLIENT_ID,
			prefix: '',
			origin: 'http://e.ly'
		};
		const browser = new Browser('http://e.ly');
		const page = await signInPage(browser, adminProject, {
			redirect_uri: 'http://e.ly/admin/callback'
		});
		const posted = await postPasskey(browser, auth, adminProject, page);
		expect(posted.status).toBe(303);
		const code = await codeAfter(browser, posted, page.url);
		expect(code.length).toBeGreaterThan(0);

		/* Activity recorded with method: 'passkey'. */
		await flushPersonActivityNow();
		const { rows } = await getPersonActivityStore().listForPerson(
			ADMIN_BUCKET_ID,
			admin._id,
			{ kind: 'signIn', outcome: 'let_in', limit: 10, now: new Date() }
		);
		expect(rows.some((r) => r.method === 'passkey')).toBe(true);

		/* Unknown credential at the Administrators sign-in page NEVER emits signalUnknownCredential. */
		const otherAuth = new SoftAuthenticator();
		await otherAuth.create(
			{
				challenge: 'other-challenge',
				rp: { id: 'e.ly' },
				user: { id: 'other-user' }
			},
			{ origin: 'http://e.ly' }
		);
		const browser2 = new Browser('http://e.ly');
		const page2 = await signInPage(browser2, adminProject, {
			redirect_uri: 'http://e.ly/admin/callback'
		});
		const refused = await postPasskey(browser2, otherAuth, adminProject, page2);
		const refusedHtml = await refused.text();
		expect(refusedHtml).not.toContain('signalUnknownCredential');
		expect(refusedHtml).not.toContain('data-unknown-credential');
	});

	it('disowns an administrator passkey via "This wasn\'t me", signs them out everywhere, alerts super admins, and sends no password reset', async () => {
		const superWatcher = await createAdministrator('super');
		await getUserStore(ADMIN_BUCKET_ID).update(superWatcher._id, {
			verified: true
		});
		const victim = await createAdministrator('plain');
		await getUserStore(ADMIN_BUCKET_ID).update(victim._id, { verified: true });
		const { cookie, sessionId } = await sessionCookieFor(victim._id, {
			signInAcr: configuration.acrMap.multi_factor,
			signInAmr: ['pwd', 'otp', 'mfa'],
			signInAt: epochTime()
		});

		const optsRes = await adminRequest(
			'POST',
			'/admin/api/me/passkeys/add/options',
			cookie
		);
		const options = shaped(OptionsShape, optsRes.body)
			.options as unknown as PublicKeyCredentialCreationOptionsJSON;
		const auth = new SoftAuthenticator();
		const cred = await auth.create(options, { origin: 'http://e.ly' });
		const addedRes = await adminRequest(
			'POST',
			'/admin/api/me/passkeys/add',
			cookie,
			{ credential: JSON.stringify(cred) }
		);
		expect(addedRes.status).toBe(201);

		const disownUrl = linkMatching(
			sent,
			/https?:\/\/[^\s"'<>]+\/account\/security\/passkey-disown\?token=[^\s"'<>]+&project=admin/
		);
		const parsedUrl = new URL(disownUrl);
		const token = present(parsedUrl.searchParams.get('token'), 'disown token');

		/* GET shows confirmation without spending. */
		const confirmPage = await elysia.handle(new Request(disownUrl));
		expect(confirmPage.status).toBe(200);
		expect(await getPasskeyStore().countOf(ADMIN_BUCKET_ID, victim._id)).toBe(
			1
		);

		/* POST disowns, signs out console session, alerts super admin, sends NO password reset. */
		const mailsBefore = sent.length;
		const postRes = await elysia.handle(
			new Request('http://e.ly/account/security/passkey-disown', {
				method: 'POST',
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
					origin: 'http://e.ly'
				},
				body: new URLSearchParams({ token, project: ADMIN_BUCKET_ID })
			})
		);
		expect(postRes.status).toBe(200);
		expect(await getPasskeyStore().countOf(ADMIN_BUCKET_ID, victim._id)).toBe(
			0
		);
		expect(await adminSessionStore.find(sessionId)).toBeNull();
		const newMails = sent.slice(mailsBefore);
		expect(
			newMails.some(
				(m) =>
					m.to === superWatcher.email &&
					m.subject.includes('unrecognised passkey')
			)
		).toBe(true);
		expect(
			newMails.some(
				(m) =>
					m.to === victim.email && m.subject.toLowerCase().includes('reset')
			)
		).toBe(false);
		const { entries } = await adminAuditStore.list({ targetId: victim._id });
		expect(entries.some((e) => e.action === 'admin.passkey.disown')).toBe(true);
	});

	it('lets a super administrator view and revoke a colleague’s passkeys via console and MCP, with secrecy, self-refusal, and non-super-admin refusal', async () => {
		const superAdmin = await createAdministrator('super');
		const colleague = await createAdministrator('plain');
		await getUserStore(ADMIN_BUCKET_ID).update(colleague._id, {
			verified: true
		});
		const colleagueSession = await sessionCookieFor(colleague._id, {
			signInAcr: configuration.acrMap.multi_factor,
			signInAmr: ['pwd', 'otp', 'mfa'],
			signInAt: epochTime()
		});

		/* Register two passkeys for colleague. */
		const addedIds: string[] = [];
		for (const label of ['Key One', 'Key Two']) {
			const optsRes = await adminRequest(
				'POST',
				'/admin/api/me/passkeys/add/options',
				colleagueSession.cookie
			);
			const options = shaped(OptionsShape, optsRes.body)
				.options as unknown as PublicKeyCredentialCreationOptionsJSON;
			const auth = new SoftAuthenticator();
			const cred = await auth.create(options, { origin: 'http://e.ly' });
			const addedRes = await adminRequest(
				'POST',
				'/admin/api/me/passkeys/add',
				colleagueSession.cookie,
				{ credential: JSON.stringify(cred), name: label }
			);
			expect(addedRes.status).toBe(201);
			addedIds.push(shaped(PasskeyRespShape, addedRes.body).passkey.id);
		}

		const { cookie: superCookie } = await sessionCookieFor(superAdmin._id);

		/* GET /admin/api/admins includes passkeys count. */
		const listAdmins = await adminRequest(
			'GET',
			'/admin/api/admins',
			superCookie
		);
		expect(listAdmins.status).toBe(200);
		const rows = listAdmins.body as unknown as Array<{
			_id: string;
			passkeys: number;
		}>;
		expect(rows.find((r) => r._id === colleague._id)?.passkeys).toBe(2);

		/* Non-super-admin is refused 403. */
		const nonSuper = await adminRequest(
			'GET',
			`/admin/api/admins/${colleague._id}/passkeys`,
			colleagueSession.cookie
		);
		expect(nonSuper.status).toBe(403);

		/* Super admin reads colleague's passkeys; zero secret fields leak. */
		const viewed = await adminRequest(
			'GET',
			`/admin/api/admins/${colleague._id}/passkeys`,
			superCookie
		);
		expect(viewed.status).toBe(200);
		const rawViewed = JSON.stringify(viewed.body);
		for (const forbidden of [
			'credentialId',
			'publicKey',
			'counter',
			'transports',
			'aaguid',
			'notMe',
			'webauthnUserId'
		]) {
			expect(rawViewed).not.toContain(forbidden);
		}

		/* Self-revocation via /admin/api/admins/:id/passkeys is refused 409. */
		const selfRevoke = await adminRequest(
			'DELETE',
			`/admin/api/admins/${superAdmin._id}/passkeys`,
			superCookie
		);
		expect(selfRevoke.status).toBe(409);

		/* Revoke one passkey via console API: signs colleague out everywhere, audits count, emails colleague. */
		const colleagueMcp = await mcpTokenFor(colleague._id);
		const mailsBefore = sent.length;
		const revokedOne = await adminRequest(
			'DELETE',
			`/admin/api/admins/${colleague._id}/passkeys/${addedIds[0]}`,
			superCookie
		);
		expect(revokedOne.status).toBe(200);
		expect(revokedOne.body.revoked).toBe(1);
		expect(revokedOne.body.mailed).toBe(true);
		expect(await adminSessionStore.find(colleagueSession.sessionId)).toBeNull();
		expect(await AccessToken.tryFind(colleagueMcp)).toBeUndefined();
		expect(sent.slice(mailsBefore).some((m) => m.to === colleague.email)).toBe(
			true
		);

		/* MCP parity: admin_passkey_list and admin_passkey_revoke_all (two-call high confirmation). */
		const superMcp = await mcpTokenFor(superAdmin._id);
		const mcpListed = await rpc(
			tool('admin_passkey_list', { id: colleague._id }),
			superMcp
		);
		expect(mcpListed.result?.isError).not.toBe(true);
		const mcpText = JSON.stringify(mcpListed.result?.structuredContent ?? {});
		expect(mcpText).toContain(addedIds[1]);
		expect(mcpText).not.toContain(addedIds[0]);
		expect(mcpText).not.toContain('credentialId');
		expect(mcpText).not.toContain('publicKey');

		const firstCall = await rpc(
			tool('admin_passkey_revoke_all', { id: colleague._id }),
			superMcp
		);
		const confirmToken = (
			firstCall.result?.structuredContent as { confirmationToken?: string }
		).confirmationToken;
		expect(typeof confirmToken).toBe('string');

		const secondCall = await rpc(
			tool('admin_passkey_revoke_all', {
				id: colleague._id,
				confirmationToken: confirmToken
			}),
			superMcp
		);
		expect(secondCall.result?.isError).not.toBe(true);
		expect(
			await getPasskeyStore().countOf(ADMIN_BUCKET_ID, colleague._id)
		).toBe(0);

		const { entries: auditEntries } = await adminAuditStore.list({
			targetId: colleague._id
		});
		expect(auditEntries.some((e) => e.action === 'admin.passkey.revoke')).toBe(
			true
		);
		expect(
			auditEntries.some((e) => e.action === 'admin.passkey.revoke.all')
		).toBe(true);
		/* Audit entries never name the passkey. */
		expect(JSON.stringify(auditEntries)).not.toContain('Key One');
		expect(JSON.stringify(auditEntries)).not.toContain('Key Two');

		/* Personal /admin/api/me/passkeys cannot be called via MCP token directly or in-process. */
		const bucket = present(
			await getBucketStore().find(ADMIN_BUCKET_ID),
			'admin bucket'
		);
		expect(rpIdFor(bucket)).toBe('e.ly');
	});
});
