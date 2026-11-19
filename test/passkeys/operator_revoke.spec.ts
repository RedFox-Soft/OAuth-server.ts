import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	spyOn
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getPasskeyStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { grantsIn } from 'lib/end_users/sessions.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { AccessToken } from 'lib/models/access_token.ts';
import { Client } from 'lib/models/client.ts';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { call as tool, rpc } from '../mcp/rpc.ts';
import * as mailer from 'lib/mail/mailer.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { present } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	Browser,
	addOnPage,
	linkIn,
	mailOn,
	mailsTo,
	person,
	presentedAt,
	project,
	redeem,
	securityPage,
	seedPasskey,
	signInWithPasskey,
	signedIn,
	type Project
} from './helpers.ts';

let acme: Project;
let cookie: string;

async function revoke(
	accountId: string,
	passkeyId?: string,
	as = cookie
): Promise<{ status: number; body: unknown }> {
	const response = await elysia.handle(
		new Request(
			`http://e.ly/admin/api/projects/${acme.bucketId}/users/${accountId}/passkeys${passkeyId === undefined ? '' : `/${passkeyId}`}`,
			{ method: 'DELETE', headers: { cookie: as } }
		)
	);
	return { status: response.status, body: await response.json() };
}

async function held(accountId: string) {
	return getPasskeyStore().listOf(acme.bucketId, accountId);
}

/* Whether this browser is still signed in to the person's page: a signed-out one is sent to sign in. */
async function signedOut(browser: Browser): Promise<boolean> {
	const page = await browser.request(securityPage(acme));
	return (
		page.status === 303 &&
		(page.headers.get('location') ?? '').includes('/auth?')
	);
}

async function entries(action: string, accountId: string) {
	return (await adminAuditStore.list({ action, targetId: accountId })).entries;
}

/*
 * A person signed in with a passkey made on `device`, on their own page and at the project's app, as whoever holds a
 * stolen one would be; plus a second passkey that stays theirs.
 */
async function signedInWithStolen(): Promise<{
	browser: Browser;
	email: string;
	accountId: string;
	stolen: string;
	device: SoftAuthenticator;
}> {
	const { browser, email, accountId } = await signedIn(acme, 'code');
	const device = new SoftAuthenticator();
	const added = await addOnPage(browser, device, acme);
	expect(added.headers.get('location')).toContain('done=passkey_added');
	const stolen = present((await held(accountId))[0], 'the passkey')._id;
	await getPasskeyStore().rename(
		acme.bucketId,
		accountId,
		stolen,
		'Work laptop'
	);
	const thief = new Browser(acme.origin);
	const { auth, code } = await signInWithPasskey(thief, device, acme);
	await redeem(acme, auth, code);
	await seedPasskey(acme.bucketId, accountId);
	return { browser: thief, email, accountId, stolen, device };
}

/**
 * @proves An administrator stops a passkey they believe stolen, or every passkey of a person: it no longer signs in, the
 * person is signed out everywhere and their grants end, they are mailed without the passkey's name, one audit entry
 * records it before the removal; their other ways in stay; a passkey already gone changes nothing; a provisioned person's
 * passkeys can be revoked; and an administrator of another team removes nothing.
 */
describe('an administrator revokes a person’s passkeys', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		cookie = await cookieFor(await createAdministrator('super'));
		acme = await project(ACME);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
	});

	afterEach(() => {
		// The one case that makes delivery fail restores it here, so a failed expectation cannot leak it.
		mockRestore();
	});

	let mockRestore: () => void = () => {};

	describe('one passkey', () => {
		it('stops it signing in, signs the person out everywhere and leaves their other ways in', async () => {
			const { browser, accountId, stolen, device } = await signedInWithStolen();
			const before = present(
				await getUserStore(acme.bucketId).find(accountId),
				'the person'
			);

			const answer = await revoke(accountId, stolen);

			expect(answer).toEqual({
				status: 200,
				body: { removed: 1, mailed: true }
			});
			expect((await presentedAt(acme, device)).status).toBe(400);
			expect(await signedOut(browser)).toBe(true);
			expect(await grantsIn(acme.bucketId, accountId)).toEqual([]);
			const after = present(
				await getUserStore(acme.bucketId).find(accountId),
				'the person'
			);
			expect(after.totp).toEqual(before.totp);
			expect(after.password).toBe(before.password);
			expect((await held(accountId)).length).toBe(1);
		});

		it('records one entry that counts it', async () => {
			const { accountId, stolen } = await signedInWithStolen();

			await revoke(accountId, stolen);

			const recorded = await entries('enduser.passkey.revoke', accountId);
			expect(recorded.length).toBe(1);
			expect(recorded[0]?.cascade).toEqual({ passkeys: 1 });
		});

		it('mails the person who removed it, without its name or a link', async () => {
			const { email, accountId, stolen } = await signedInWithStolen();
			resetSentEmails();

			await revoke(accountId, stolen);

			const mails = mailsTo(email);
			expect(mails.length).toBe(1);
			const mail = present(mails[0], 'the mail');
			expect(mail.subject).toContain('A passkey was removed');
			expect(mail.text).toContain('The people who run');
			expect(mail.text).toContain('You were signed out everywhere.');
			for (const part of [mail.subject, mail.text, mail.html]) {
				expect(part).not.toContain('Work laptop');
				expect(part).not.toContain('http');
			}
		});

		it('changes nothing when the passkey is already gone', async () => {
			const { email, accountId, stolen } = await signedInWithStolen();
			await revoke(accountId, stolen);
			const { browser } = await signedIn(acme, 'code', { email, accountId });
			resetSentEmails();

			const again = await revoke(accountId, stolen);

			expect(again.status).toBe(404);
			expect(await signedOut(browser)).toBe(false);
			expect(mailsTo(email)).toEqual([]);
		});

		it('removes nothing given another person’s passkey', async () => {
			const { accountId } = await person(acme.bucketId);
			const other = await person(acme.bucketId);
			const theirs = await seedPasskey(acme.bucketId, other.accountId);

			const answer = await revoke(accountId, theirs._id);

			expect(answer.status).toBe(404);
			expect((await held(other.accountId)).length).toBe(1);
		});

		it('removes nothing for an administrator of another team', async () => {
			const { accountId } = await person(acme.bucketId);
			const passkey = await seedPasskey(acme.bucketId, accountId);
			const outsider = await cookieFor(await createAdministrator('plain'));

			const answer = await revoke(accountId, passkey._id, outsider);

			expect([403, 404]).toContain(answer.status);
			expect((await held(accountId)).length).toBe(1);
		});

		it('revokes a passkey of a person a provisioning connection manages', async () => {
			const { accountId } = await person(acme.bucketId);
			await getUserStore(acme.bucketId).update(accountId, {
				provisionedBy: 'a-connection'
			});
			const passkey = await seedPasskey(acme.bucketId, accountId);

			const answer = await revoke(accountId, passkey._id);

			expect(answer.status).toBe(200);
			expect(await held(accountId)).toEqual([]);
		});

		it('revokes a person’s last way in', async () => {
			const { accountId } = await person(acme.bucketId);
			await getUserStore(acme.bucketId).update(accountId, {
				passwordSet: false
			});
			const passkey = await seedPasskey(acme.bucketId, accountId);

			const answer = await revoke(accountId, passkey._id);

			expect(answer.status).toBe(200);
			expect(await held(accountId)).toEqual([]);
		});

		it('says it could not mail someone whose address is not confirmed, and revokes', async () => {
			const { accountId } = await person(acme.bucketId);
			await getUserStore(acme.bucketId).update(accountId, { verified: false });
			const passkey = await seedPasskey(acme.bucketId, accountId);

			const answer = await revoke(accountId, passkey._id);

			expect(answer).toEqual({
				status: 200,
				body: { removed: 1, mailed: false }
			});
		});

		it('says it could not mail when delivery fails, and revokes', async () => {
			const { accountId } = await person(acme.bucketId);
			const passkey = await seedPasskey(acme.bucketId, accountId);
			const failing = spyOn(mailer, 'deliver').mockRejectedValue(
				new Error('refused')
			);
			mockRestore = () => failing.mockRestore();
			const quiet = spyOn(console, 'error').mockImplementation(() => {});

			const answer = await revoke(accountId, passkey._id);
			quiet.mockRestore();

			expect(answer).toEqual({
				status: 200,
				body: { removed: 1, mailed: false }
			});
			expect(await held(accountId)).toEqual([]);
		});

		it('leaves its “This wasn’t me” link changing nothing', async () => {
			const { browser, email, accountId } = await signedIn(acme, 'code');
			await addOnPage(browser, new SoftAuthenticator(), acme);
			const link = linkIn(email, '/account/security/passkey-disown');
			const passkey = present((await held(accountId))[0], 'the passkey');
			await revoke(accountId, passkey._id);
			const after = await signedIn(acme, 'code', { email, accountId });

			const owner = new Browser(acme.origin);
			await owner.request(link);
			await owner.post(new URL(link).pathname, {
				token: present(new URL(link).searchParams.get('token'), 'a token')
			});

			expect(await signedOut(after.browser)).toBe(false);
		});
	});

	describe('through an agent', () => {
		let rpcId = 0;

		/* An agent's token for a super administrator, after the MCP handshake its client makes. */
		async function agentToken(): Promise<string> {
			ApplicationConfig['mcp.enabled'] = true;
			const user = await createAdministrator('super');
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
			return token;
		}

		it('revokes nothing until the call is confirmed, then does what the console does', async () => {
			const { email, accountId } = await person(acme.bucketId);
			const passkey = await seedPasskey(acme.bucketId, accountId);
			const token = await agentToken();
			const args = {
				id: acme.bucketId,
				uid: accountId,
				passkeyId: passkey._id
			};
			resetSentEmails();

			const asked = await rpc(tool('project_user_passkey_revoke', args), token);
			const confirmationToken =
				asked.result?.structuredContent?.confirmationToken;

			expect(asked.result?.structuredContent?.status).toBe(
				'confirmation_required'
			);
			expect((await held(accountId)).length).toBe(1);

			const done = await rpc(
				tool('project_user_passkey_revoke', { ...args, confirmationToken }),
				token
			);

			expect(done.result?.isError).not.toBe(true);
			expect(await held(accountId)).toEqual([]);
			expect(mailsTo(email).length).toBe(1);
			const recorded = await entries('enduser.passkey.revoke', accountId);
			expect(recorded.map((entry) => entry.viaSurface)).toEqual(['mcp']);
		});

		it('lists a person’s passkeys as the console reads them', async () => {
			const { accountId } = await person(acme.bucketId);
			const passkey = await seedPasskey(acme.bucketId, accountId);
			const token = await agentToken();

			const listed = await rpc(
				tool('project_user_passkey_list', {
					id: acme.bucketId,
					uid: accountId
				}),
				token
			);

			expect(listed.result?.isError).not.toBe(true);
			const text = JSON.stringify(listed.result?.structuredContent ?? {});
			expect(text).toContain(passkey._id);
			expect(text).not.toContain(passkey.credentialId);
			expect(text).not.toContain(passkey.publicKey);
		});
	});

	describe('every passkey', () => {
		it('removes them all with one sign-out, one mail and one entry', async () => {
			const { browser, email, accountId } = await signedInWithStolen();
			await seedPasskey(acme.bucketId, accountId);
			resetSentEmails();

			const answer = await revoke(accountId);

			expect(answer).toEqual({
				status: 200,
				body: { removed: 3, mailed: true }
			});
			expect(await held(accountId)).toEqual([]);
			expect(await signedOut(browser)).toBe(true);
			expect(await grantsIn(acme.bucketId, accountId)).toEqual([]);
			const mails = mailsTo(email);
			expect(mails.length).toBe(1);
			expect(mails[0]?.text).toContain('(3 in all)');
			const recorded = await entries('enduser.passkey.revoke.all', accountId);
			expect(recorded.length).toBe(1);
			expect(recorded[0]?.cascade).toEqual({ passkeys: 3 });
		});

		it('changes nothing for someone holding none', async () => {
			const { browser, email, accountId } = await signedIn(acme, 'code');
			resetSentEmails();

			const answer = await revoke(accountId);

			expect(answer.status).toBe(404);
			expect(await signedOut(browser)).toBe(false);
			expect(mailsTo(email)).toEqual([]);
			expect(await entries('enduser.passkey.revoke.all', accountId)).toEqual(
				[]
			);
		});
	});
});
