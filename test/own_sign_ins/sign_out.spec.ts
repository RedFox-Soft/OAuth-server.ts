import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { createAppSession, readAppSession } from 'lib/behind_proxy/session.ts';
import { ACCOUNT_TEXTS } from 'lib/i18n/texts/account/index.ts';
import { text as fill } from 'lib/i18n/message.tsx';
import { request as requestReset } from 'lib/password_reset/challenge.ts';
import { Session } from 'lib/models/session.ts';
import { resetSentEmails, sentEmails } from '../mail_capture.ts';
import { provider } from '../scim/helpers.ts';
import { giveAccess, introspect, refresh } from '../connected_apps/helpers.ts';
import {
	appBehindProxy,
	Browser,
	openPage,
	PAGE,
	reshapeSession,
	sessionIdOf,
	signedIn,
	STALE,
	textOf,
	xsrfFrom
} from './helpers.ts';

const T = ACCOUNT_TEXTS.en;

/* Opens the confirmation and confirms it, as the page's form does. */
async function signOutEverywhere(browser: Browser): Promise<Response> {
	const { html } = await openPage(browser, '?confirm=1');
	return browser.post(PAGE, { xsrf: xsrfFrom(html) });
}

async function providerOnly(accountId: string): Promise<void> {
	await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
		passwordSet: false,
		federated: [
			{ providerId: 'corp', sub: `corp-${accountId}`, linkedAt: new Date() }
		]
	});
}

/**
 * @proves A person who does not recognise a sign-in signs out everywhere from Recent sign-ins: every session, grant,
 * refresh token, access token and app session behind the proxy ends; a person with a password is mailed the usual
 * link to set a new one, or told when it could not be sent; a person who signs in through a provider is told to change
 * their password there.
 */
describe('signing out everywhere from recent sign-ins', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'own_sign_ins' });
	});

	beforeEach(async () => {
		resetSentEmails();
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			passwordLogin: true,
			federation: [provider('corp', { displayName: 'Acme SSO' })]
		});
	});

	it('ends sessions, grants, refresh tokens, access tokens and app sessions behind the proxy', async () => {
		const { browser, accountId } = await signedIn();
		const sessionId = await sessionIdOf(browser);
		const access = await giveAccess(
			browser,
			'own-app',
			'openid offline_access'
		);
		const app = await appBehindProxy('Acme wiki', 'https://wiki.acme.test');
		const scope = { appId: app._id, bucketId: DEFAULT_BUCKET_ID };
		const appSession = await createAppSession(scope, accountId);

		const done = await signOutEverywhere(browser);

		expect(done.status).toBe(200);
		expect(textOf(await done.text())).toContain(T.signOutDoneTitle);
		expect(await Session.tryFind(sessionId)).toBeUndefined();
		expect(
			(await refresh('own-app', access.refreshToken ?? '')).error
		).toBeTruthy();
		expect(await introspect(access.accessToken)).toMatchObject({
			active: false
		});
		expect(await readAppSession(scope, appSession)).toBeNull();
	});

	it('mails a reset link to a person with a password', async () => {
		const { browser, email } = await signedIn();

		const done = await signOutEverywhere(browser);

		expect(textOf(await done.text())).toContain(
			fill(T.signOutDoneMail, { email })
		);
		expect(sentEmails.filter((mail) => mail.to === email)).toHaveLength(1);
		expect(sentEmails.at(-1)?.text).toContain('/reset-password?token=');
	});

	it('still signs out and says the email was not sent when the reset is throttled', async () => {
		const { browser, email } = await signedIn();
		await requestReset(email, DEFAULT_BUCKET_ID);
		resetSentEmails();

		const done = await signOutEverywhere(browser);
		const shown = textOf(await done.text());

		expect(shown).toContain(T.signOutDoneTitle);
		expect(shown).toContain('choose "Forgot password');
		expect(sentEmails).toHaveLength(0);
	});

	it('tells a provider-only person to change their password at the provider and mails nothing', async () => {
		const { browser, accountId } = await signedIn();
		await providerOnly(accountId);

		const { html } = await openPage(browser, '?confirm=1');
		const done = await browser.post(PAGE, { xsrf: xsrfFrom(html) });

		expect(textOf(html)).toContain(
			fill(T.signOutProvider, { providers: 'Acme SSO' })
		);
		expect(textOf(html)).not.toContain(T.signOutMail);
		expect(done.status).toBe(200);
		expect(sentEmails).toHaveLength(0);
	});

	it('mails nothing in a project without password sign-in', async () => {
		const { browser } = await signedIn();
		await getBucketStore().update(DEFAULT_BUCKET_ID, { passwordLogin: false });

		const { html } = await openPage(browser, '?confirm=1');
		const done = await browser.post(PAGE, { xsrf: xsrfFrom(html) });

		expect(textOf(html)).not.toContain(T.signOutMail);
		expect(done.status).toBe(200);
		expect(sentEmails).toHaveLength(0);
	});

	it('asks a stale session to sign in again before showing the confirmation', async () => {
		const { browser } = await signedIn();
		await reshapeSession(browser, { ageSeconds: STALE });

		const { response } = await openPage(browser, '?confirm=1');

		expect(response.status).toBe(303);
		expect(response.headers.get('location')).toContain('prompt=login');
	});
});
