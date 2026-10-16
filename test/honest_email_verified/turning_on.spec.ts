import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import bootstrap from '../test_helper.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getSmtpSettingsStore } from 'lib/adapters/index.ts';
import type { SmtpSettings } from 'lib/adapters/types.ts';
import { call, superAdmin } from '../plans/admin.ts';
import { emailsTo, resetSentEmails } from '../mail_capture.ts';
import { projectFor, signIn, signUp } from './sign_up.ts';

const CLIENT = 'honest-off-app';
const MAIL: SmtpSettings = {
	host: 'smtp.example.test',
	port: 587,
	secure: false,
	username: '',
	password: '',
	fromName: 'Honest',
	fromEmail: 'honest@example.test'
};

/**
 * @proves Turning verification on reaches everyone who signed up while it was off and never proved their address:
 * the preview counts them, and their next sign-in sends the message and does not complete.
 */
describe('turning verification on after people signed up without it', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'honest_email_verified' });
		await ensureAdminSeed();
		await getSmtpSettingsStore().set(MAIL);
	});

	afterAll(async () => {
		await getSmtpSettingsStore().set({ ...MAIL, host: '', fromEmail: '' });
	});

	it('counts them in the preview and asks them at their next sign-in', async () => {
		const projectId = await projectFor(CLIENT, false);
		const email = `early-${Date.now()}@honest.test`;
		await signUp(CLIENT, email);
		const operator = await superAdmin();
		const path = `/admin/api/projects/${projectId}`;

		const preview = await call('PATCH', path, operator.cookie, {
			emailVerificationRequired: true
		});
		const counted = (preview.body as { expect?: { unverified?: number } })
			.expect?.unverified;
		const saved = await call('PATCH', path, operator.cookie, {
			emailVerificationRequired: true,
			confirm: true,
			expect: (preview.body as { expect: Record<string, number> }).expect
		});
		resetSentEmails();
		const status = await signIn(CLIENT, email);

		expect(preview.status).toBe(409);
		expect(counted).toBe(1);
		expect(saved.status).toBe(200);
		expect(status).toBe(400);
		expect(emailsTo(email)).toHaveLength(1);
	});
});
