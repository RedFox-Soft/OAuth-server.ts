import { describe, it, expect, beforeEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { smtpSettingsRoutes } from 'lib/admin/settings/smtp/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminAuditStore, getSmtpSettingsStore } from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { sentEmails } from 'lib/mail/mailer.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import { emailsTo, resetSentEmails } from '../mail_capture.ts';

const app = new Elysia().use(resolveAdmin).use(smtpSettingsRoutes);

const MAIL = {
	host: 'smtp.example.com',
	port: 465,
	secure: true,
	username: 'hello@example.com',
	password: 's3cret',
	fromName: 'Example',
	fromEmail: 'no-reply@example.com'
};

async function signedIn(kind: AdminKind) {
	const email = `${kind}-${Math.random()}@x.io`;
	const user = await createAdministrator(kind, email);
	const s = await sessionFor(user);
	return { email, cookie: `${ADMIN_SESSION_COOKIE}=${s._id}` };
}

async function sendTest(cookie: string, body?: unknown) {
	const res = await app.handle(
		new Request('http://e.ly/admin/api/settings/smtp/test', {
			method: 'POST',
			headers: {
				cookie,
				...(body === undefined ? {} : { 'content-type': 'application/json' })
			},
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	return {
		status: res.status,
		body: (await res.json()) as { sent?: boolean; to?: string; error?: string }
	};
}

/**
 * @proves A super administrator learns whether this server can send mail, and when it cannot, the mail
 * server's own reason; the test reaches only their own mailbox.
 */
describe('sending a test message from the mail settings', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
		await getSmtpSettingsStore().set(MAIL);
		resetSentEmails();
	});

	it('sends a test message to the administrator who asked, and records that it did', async () => {
		const { email, cookie } = await signedIn('super');

		const res = await sendTest(cookie);

		expect(res.status).toBe(200);
		expect(res.body).toEqual({ sent: true, to: email });
		expect(emailsTo(email)).toHaveLength(1);
		const { entries } = await adminAuditStore.list({
			targetType: 'SmtpSettings'
		});
		expect(entries[0]?.action).toBe('smtp.settings.test');
	});

	it('answers a refusal with the mail server’s own reply', async () => {
		const { cookie } = await signedIn('super');
		const refusal = Object.assign(new Error('Invalid login'), {
			code: 'EAUTH',
			response: '535 5.7.8 Authentication failed'
		});
		const push = spyOn(sentEmails, 'push').mockImplementation(() => {
			throw refusal;
		});
		try {
			const res = await sendTest(cookie);

			expect(res.status).toBe(502);
			expect(JSON.stringify(res.body)).toContain(
				'535 5.7.8 Authentication failed (EAUTH)'
			);
		} finally {
			push.mockRestore();
		}
	});

	it('sends nothing while mail delivery is not configured', async () => {
		await getSmtpSettingsStore().set({ ...MAIL, host: '', fromEmail: '' });
		const { cookie } = await signedIn('super');

		const res = await sendTest(cookie);

		expect(res.status).toBe(409);
		expect(sentEmails).toHaveLength(0);
	});

	it('cannot be pointed at anyone else’s address', async () => {
		const { email, cookie } = await signedIn('super');

		const res = await sendTest(cookie, { to: 'someone-else@example.org' });

		expect(emailsTo('someone-else@example.org')).toHaveLength(0);
		if (res.status === 200) expect(emailsTo(email)).toHaveLength(1);
	});

	it('is refused to an administrator who is not a super administrator', async () => {
		const { cookie } = await signedIn('plain');

		const res = await sendTest(cookie);

		expect(res.status).toBe(403);
		expect(sentEmails).toHaveLength(0);
	});
});
