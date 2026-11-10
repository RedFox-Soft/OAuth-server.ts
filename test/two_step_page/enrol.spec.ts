import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap, { encodeParams } from '../test_helper.js';
import { adminAuditStore, getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { configuration } from 'lib/configs/application.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { present } from '../shape.ts';
import {
	Browser,
	enrol,
	mailOn,
	mailsTo,
	person,
	project,
	signedIn
} from './helpers.ts';
import { signInThroughPage } from '../connected_apps/helpers.ts';

/* The ID token an app receives when it sends this browser to sign in again: what the app learns about the sign-in. */
async function idTokenClaims(
	browser: Browser
): Promise<Record<string, unknown>> {
	const auth = new AuthorizationRequest({
		client_id: 'two-step-app',
		scope: 'openid'
	});
	const step = await browser.open(`/auth?${encodeParams(auth.params)}`);
	const code = present(
		new URL(step.url).searchParams.get('code'),
		`a code (ended at ${step.url})`
	);
	const { data } = await auth.getToken(code);
	const idToken = present(
		(data as { id_token?: string } | null)?.id_token,
		'an ID token'
	);
	return JSON.parse(
		Buffer.from(
			present(idToken.split('.')[1], 'a payload'),
			'base64url'
		).toString()
	) as Record<string, unknown>;
}

/**
 * @proves A person in a project that does not require an authenticator app turns two-step verification on for their
 * own account, after a fresh password sign-in and a link mailed to them, and is told so by mail.
 */
describe('turning on two-step verification on your own page', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await project();
	});

	afterEach(async () => {
		await project();
	});

	it('sets up the authenticator app after the mailed link and a right code', async () => {
		const { browser, email, accountId } = await signedIn();

		await enrol(browser, email);

		const user = present(
			await getUserStore(DEFAULT_BUCKET_ID).find(accountId),
			'the person'
		);
		expect(user.totp?.via).toBe('self');
		expect(user.totpProofRequired).toBeUndefined();
	});

	it('records the address as confirmed, since the link proved it', async () => {
		const { email, accountId } = await person();
		await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
			verified: false
		});
		const browser = new Browser();
		await signInThroughPage(browser, email);

		await enrol(browser, email);

		expect(
			(await getUserStore(DEFAULT_BUCKET_ID).find(accountId))?.verified
		).toBe(true);
	});

	it('tells the person by mail that it was turned on, with a way to undo it', async () => {
		const { browser, email } = await signedIn();

		await enrol(browser, email);

		const subjects = mailsTo(email).map((mail) => mail.subject);
		expect(subjects).toContain(
			'Two-step verification was turned on for your default account'
		);
		const notice = present(mailsTo(email).at(-1), 'the notice');
		expect(notice.text).toContain('/account/security/disown?token=');
	});

	it('writes the mail in the language the person chose', async () => {
		const { email, accountId } = await person();
		await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
			profile: { locale: 'ru' }
		});
		const browser = new Browser();
		await signInThroughPage(browser, email);

		await enrol(browser, email);

		expect(present(mailsTo(email).at(-1), 'the notice').language).toBe('ru');
	});

	it('leaves one audit entry naming the person as the actor', async () => {
		const { browser, email, accountId } = await signedIn();

		await enrol(browser, email);

		const { entries } = await adminAuditStore.list({ targetId: accountId });
		const enrolments = entries.filter((e) => e.action === 'enduser.totp.enrol');
		expect(enrolments).toHaveLength(1);
		expect(enrolments[0]?.actorId).toBe(
			`enduser:${DEFAULT_BUCKET_ID}:${accountId}`
		);
	});

	it('counts the sign-in as multi-factor afterwards when the password was just entered', async () => {
		const { browser, email } = await signedIn();

		await enrol(browser, email);

		expect((await idTokenClaims(browser)).acr).toBe(
			configuration.acrMap.multi_factor
		);
	});
});
