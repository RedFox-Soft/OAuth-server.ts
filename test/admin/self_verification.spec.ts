import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import bootstrap, { agent } from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { elysia } from 'lib/index.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import {
	resetSentEmails,
	emailsTo,
	extractVerifyUrl
} from '../mail_capture.ts';
import { present } from 'test/shape.js';

async function call(method: 'GET' | 'POST', path: string, cookie: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, { method, headers: { cookie } })
	);
	return {
		status: res.status,
		body: (await res.json()) as Record<string, unknown>
	};
}

async function signedInAdministrator() {
	const user = await createAdministrator('plain');
	const session = await sessionFor(user);
	return { user, cookie: `${ADMIN_SESSION_COOKIE}=${session._id}` };
}

/**
 * @proves An administrator can prove their own address from the console, which is what a super
 * administrator must do before requiring it of everyone.
 */
describe('verifying your own address from the console', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'admin' });
		await ensureAdminSeed();
	});

	beforeEach(() => {
		resetSentEmails();
	});

	it('mails the administrator a link that verifies their address', async () => {
		const { user, cookie } = await signedInAdministrator();

		const sent = await call('POST', '/admin/api/me/verification', cookie);
		expect(sent.status).toBe(200);
		expect(sent.body.sent).toBe(true);

		const url = present(
			extractVerifyUrl(present(emailsTo(user.email)[0], 'message')),
			'link'
		);
		const token = present(new URL(url).searchParams.get('token'), 'token');
		const opened = await agent['verify-email'].get({ query: { token } });
		expect(opened.response.status).toBe(200);

		const me = await call('GET', '/admin/api/me', cookie);
		expect(me.body.verified).toBe(true);
	});

	it('tells an administrator whose address is already verified so, and sends nothing', async () => {
		const { user, cookie } = await signedInAdministrator();
		await getUserStore(ADMIN_BUCKET_ID).update(user._id, { verified: true });

		const res = await call('POST', '/admin/api/me/verification', cookie);
		expect(res.status).toBe(200);
		expect(res.body.alreadyVerified).toBe(true);
		expect(emailsTo(user.email)).toHaveLength(0);
	});
});
