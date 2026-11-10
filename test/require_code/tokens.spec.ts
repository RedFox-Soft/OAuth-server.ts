import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap, { changeClient } from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { present } from '../shape.ts';
import { refresh } from '../connected_apps/helpers.ts';
import {
	Browser,
	codeFor,
	mailOn,
	openApp,
	person,
	PLAIN_APP,
	project,
	typePassword
} from './helpers.ts';

const SECRET = 'JBSWY3DPEHPK3PXP';

let restore: (() => Promise<void>) | undefined;

async function requireCode(): Promise<void> {
	restore = await changeClient(PLAIN_APP, { 'signIn.requireCode': true });
}

/* A sign-in to the application while it does not yet require a code; answers the code it received, unredeemed. */
async function codeFromSignIn(withFactor: boolean) {
	const { email, accountId } = await person();
	if (withFactor) {
		await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
			totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0, via: 'self' }
		});
	}
	const browser = new Browser();
	const opened = await openApp(browser, PLAIN_APP, {
		scope: 'openid offline_access',
		prompt: 'consent'
	});
	let landed = await typePassword(browser, opened.url, email);
	if (withFactor) {
		const uid = present(
			/\/ui\/([^/]+)\/totp$/.exec(landed.url)?.[1],
			'the code step'
		);
		const answered = await browser.post(`/ui/${uid}/totp`, {
			code: codeFor(SECRET)
		});
		landed = await browser.open(
			new URL(
				present(answered.headers.get('location'), 'a resume'),
				browser.url(`/ui/${uid}/`)
			).toString()
		);
	}
	const code = present(
		new URL(landed.url).searchParams.get('code'),
		`a code (ended at ${landed.url})`
	);
	return { auth: opened.auth, code };
}

/**
 * @proves While an application requires a code, no token that acts for a person is issued to it on the strength of a
 * sign-in that gave none: a code issued in the moment before the requirement, and a refresh token from a sign-in
 * without one, are refused; one from a sign-in with a code keeps working.
 */
describe('tokens for an application that requires a code', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await project();
	});

	afterEach(async () => {
		await restore?.();
		restore = undefined;
	});

	it('refuses a code issued before the requirement, from a sign-in without one', async () => {
		const { auth, code } = await codeFromSignIn(false);
		await requireCode();

		const { error } = await auth.getToken(code);

		expect(error?.status).toBe(400);
		expect(error?.value).toMatchObject({ error: 'invalid_grant' });
	});

	it('refuses a refresh token from a sign-in without a code', async () => {
		const { auth, code } = await codeFromSignIn(false);
		const { data } = await auth.getToken(code);
		const refreshToken = present(
			(data as { refresh_token?: string } | null)?.refresh_token,
			'a refresh token'
		);
		await requireCode();

		const { error } = await refresh(PLAIN_APP, refreshToken);

		expect(error?.status).toBe(400);
		expect(error?.value).toMatchObject({ error: 'invalid_grant' });
	});

	it('keeps a refresh token from a sign-in with a code working', async () => {
		const { auth, code } = await codeFromSignIn(true);
		const { data } = await auth.getToken(code);
		const refreshToken = present(
			(data as { refresh_token?: string } | null)?.refresh_token,
			'a refresh token'
		);
		await requireCode();

		const { data: renewed } = await refresh(PLAIN_APP, refreshToken);

		expect(
			(renewed as { access_token?: string } | null)?.access_token
		).toBeString();
	});
});
