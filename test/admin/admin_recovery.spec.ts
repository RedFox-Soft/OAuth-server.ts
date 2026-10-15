import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminAuditStore, getUserStore } from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import { shaped } from 'test/shape.ts';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from './ownership_fixtures.ts';

async function request(
	method: string,
	path: string,
	cookie: string
): Promise<{ status: number; body: unknown }> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, { method, headers: { cookie } })
	);
	const text = await response.text();
	return {
		status: response.status,
		body: text ? (JSON.parse(text) as unknown) : null
	};
}

const Ended = Type.Object({ sessions: Type.Number() });
const Refusal = Type.Object({ message: Type.String() });

const ENROLMENT = {
	secret: 'JBSWY3DPEHPK3PXP',
	enrolledAt: new Date(),
	lastStep: 0
};

async function recorded(action: string, targetId: string): Promise<number> {
	const { entries } = await adminAuditStore.list({ targetId, action });
	return entries.length;
}

/* Whether a console session still opens the console. */
async function stillSignedIn(cookie: string): Promise<boolean> {
	return (await request('GET', '/admin/api/projects', cookie)).status !== 401;
}

/**
 * @proves A super administrator recovers a colleague: signing them out everywhere ends every console
 * session they hold while leaving the account as it was, and resetting their authenticator clears it and
 * signs them out; neither can be done to oneself, to an account without an authenticator to reset, or by an
 * administrator who is not a super administrator, and a refusal records nothing.
 */
describe("recovering an administrator's access", () => {
	let superCookie: string;
	let acting: User;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		acting = await createAdministrator('super');
		superCookie = await cookieFor(acting);
	});

	describe('signing a colleague out everywhere', () => {
		it('ends every console session they hold, so their next request has to sign in again', async () => {
			const colleague = await createAdministrator();
			const laptop = await cookieFor(colleague);
			const phone = await cookieFor(colleague);

			const answer = await request(
				'POST',
				`/admin/api/admins/${colleague._id}/sign-out`,
				superCookie
			);

			expect(answer.status).toBe(200);
			expect(shaped(Ended, answer.body)).toEqual({ sessions: 2 });
			expect([await stillSignedIn(laptop), await stillSignedIn(phone)]).toEqual(
				[false, false]
			);
		});

		it('ends the token an agent acting for them holds', async () => {
			const colleague = await createAdministrator();
			const issued = new AccessToken({
				client: await Client.find(ADMIN_MCP_CLIENT_ID),
				accountId: colleague._id,
				scope: 'openid'
			});
			issued.setAudience(MCP_RESOURCE);
			const token = await issued.save();

			await request(
				'POST',
				`/admin/api/admins/${colleague._id}/sign-out`,
				superCookie
			);

			expect(await AccessToken.tryFind(token)).toBeFalsy();
		});

		it('leaves their account able to sign in, and the caller signed in', async () => {
			const colleague = await createAdministrator();
			await cookieFor(colleague);

			await request(
				'POST',
				`/admin/api/admins/${colleague._id}/sign-out`,
				superCookie
			);

			const account = await getUserStore(ADMIN_BUCKET_ID).find(colleague._id);
			expect(account?.active).toBe(true);
			expect(await stillSignedIn(superCookie)).toBe(true);
		});

		it('is recorded against the colleague', async () => {
			const colleague = await createAdministrator();

			await request(
				'POST',
				`/admin/api/admins/${colleague._id}/sign-out`,
				superCookie
			);

			expect(await recorded('admin.signout', colleague._id)).toBe(1);
		});

		it('is refused on oneself, who signs out with Log out, and records nothing', async () => {
			const answer = await request(
				'POST',
				`/admin/api/admins/${acting._id}/sign-out`,
				superCookie
			);

			expect(answer.status).toBe(409);
			expect(shaped(Refusal, answer.body).message).toBe(
				'you cannot sign yourself out from here — use Log out'
			);
			expect(await stillSignedIn(superCookie)).toBe(true);
			expect(await recorded('admin.signout', acting._id)).toBe(0);
		});

		it('answers not found for an administrator who does not exist', async () => {
			const answer = await request(
				'POST',
				'/admin/api/admins/nobody-here/sign-out',
				superCookie
			);

			expect(answer.status).toBe(404);
		});

		it('is refused to an administrator who is not a super administrator', async () => {
			const colleague = await createAdministrator();
			const session = await cookieFor(colleague);
			const plain = await cookieFor(await createAdministrator());

			const answer = await request(
				'POST',
				`/admin/api/admins/${colleague._id}/sign-out`,
				plain
			);

			expect(answer.status).toBe(403);
			expect(await stillSignedIn(session)).toBe(true);
		});
	});

	describe("resetting a colleague's authenticator", () => {
		async function enrolled(): Promise<User> {
			const colleague = await createAdministrator();
			await getUserStore(ADMIN_BUCKET_ID).update(colleague._id, {
				totp: ENROLMENT
			});
			return colleague;
		}

		it('clears it, so they enrol afresh at their next sign-in, and signs them out', async () => {
			const colleague = await enrolled();
			const session = await cookieFor(colleague);

			const answer = await request(
				'DELETE',
				`/admin/api/admins/${colleague._id}/totp`,
				superCookie
			);

			expect(answer.status).toBe(200);
			expect(shaped(Ended, answer.body)).toEqual({ sessions: 1 });
			expect(
				(await getUserStore(ADMIN_BUCKET_ID).find(colleague._id))?.totp
			).toBeUndefined();
			expect(await stillSignedIn(session)).toBe(false);
			expect(await recorded('admin.totp.clear', colleague._id)).toBe(1);
		});

		it('is refused when they have no authenticator, and records nothing', async () => {
			const colleague = await createAdministrator();
			const session = await cookieFor(colleague);

			const answer = await request(
				'DELETE',
				`/admin/api/admins/${colleague._id}/totp`,
				superCookie
			);

			expect(answer.status).toBe(409);
			expect(shaped(Refusal, answer.body).message).toBe(
				'no authenticator to reset'
			);
			expect(await stillSignedIn(session)).toBe(true);
			expect(await recorded('admin.totp.clear', colleague._id)).toBe(0);
		});

		it('is refused on oneself, and leaves the authenticator in place', async () => {
			await getUserStore(ADMIN_BUCKET_ID).update(acting._id, {
				totp: ENROLMENT
			});
			try {
				const answer = await request(
					'DELETE',
					`/admin/api/admins/${acting._id}/totp`,
					superCookie
				);

				expect(answer.status).toBe(409);
				expect(
					(await getUserStore(ADMIN_BUCKET_ID).find(acting._id))?.totp
				).toBeDefined();
			} finally {
				await getUserStore(ADMIN_BUCKET_ID).update(acting._id, {
					totp: undefined
				});
			}
		});

		it('is refused to an administrator who is not a super administrator', async () => {
			const colleague = await enrolled();
			const plain = await cookieFor(await createAdministrator());

			const answer = await request(
				'DELETE',
				`/admin/api/admins/${colleague._id}/totp`,
				plain
			);

			expect(answer.status).toBe(403);
			expect(
				(await getUserStore(ADMIN_BUCKET_ID).find(colleague._id))?.totp
			).toBeDefined();
		});
	});
});
