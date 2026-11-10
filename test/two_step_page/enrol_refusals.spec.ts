import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime,
	spyOn
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { adminAuditStore, getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { configuration } from 'lib/configs/application.ts';
import { sessionCookieName } from 'lib/consts/param_list.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { Session } from 'lib/models/session.ts';
import { verifyForAccount } from 'lib/totp/verify.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { present } from '../shape.ts';
import { signInThroughPage } from '../connected_apps/helpers.ts';
import {
	Browser,
	codeFor,
	enrol,
	keyFrom,
	linkIn,
	mailOn,
	mailsTo,
	openPage,
	PAGE,
	person,
	project,
	signedIn,
	startAndFollow
} from './helpers.ts';

const LINK_PATH = '/account/security/link';

async function sessionOf(browser: Browser): Promise<Session> {
	const bucket = present(
		await getBucketStore().find(DEFAULT_BUCKET_ID),
		'the bucket'
	);
	const name = sessionCookieName(bucket);
	const id = present(
		browser.cookie
			.split('; ')
			.find((pair) => pair.startsWith(`${name}=`))
			?.slice(name.length + 1),
		'a session cookie'
	);
	return present(await Session.tryFind(id), 'the session');
}

/* The browser's sign-in, rewritten as one that went through a provider: no password was typed. */
async function asProviderSignIn(browser: Browser): Promise<void> {
	const session = await sessionOf(browser);
	session.payload.amr = [];
	session.payload.acr = configuration.acrMap.federated;
	await session.save(
		(session.payload.exp ?? 0) - Math.floor(Date.now() / 1000)
	);
}

/* Posts the page's start action with the session's own anti-forgery value, as its form would if it were shown. */
async function start(browser: Browser): Promise<Response> {
	await openPage(browser).catch(() => undefined);
	const xsrf = present(
		(await sessionOf(browser)).payload.accountPageXsrf,
		'the page’s anti-forgery value'
	);
	return browser.post(PAGE, { action: 'start', xsrf });
}

/* Keeps the browser's password sign-in fresh, as if the person had just typed it again. */
async function freshen(browser: Browser): Promise<void> {
	const session = await sessionOf(browser);
	session.payload.loginTs = Math.floor(Date.now() / 1000);
	await session.save(
		(session.payload.exp ?? 0) - Math.floor(Date.now() / 1000)
	);
}

function linkMailsTo(email: string) {
	return mailsTo(email).filter((mail) => mail.text.includes(LINK_PATH));
}

/**
 * @proves Two-step verification cannot be turned on by someone who holds only a provider sign-in, only a password-less
 * account, only the mailed link in another browser, or a link that expired, was used, or was replaced; and the
 * secret never reaches the audit trail.
 */
describe('turning on two-step verification without the proof it needs', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await project();
	});

	afterEach(async () => {
		setSystemTime();
		await mailOn();
		await project();
	});

	it('asks for a password sign-in first when the session came through a provider, and mails nothing', async () => {
		const { browser, email } = await signedIn();
		await asProviderSignIn(browser);

		const started = await start(browser);

		expect(started.status).toBe(303);
		expect(
			new URL(present(started.headers.get('location'), 'a location')).pathname
		).toBe('/auth');
		expect(linkMailsTo(email)).toHaveLength(0);
	});

	it('offers nothing to a person who has no password', async () => {
		const { email, accountId } = await person();
		const browser = new Browser();
		await signInThroughPage(browser, email);
		await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
			passwordSet: false
		});

		const html = await (await browser.request(PAGE)).text();
		await start(browser);

		expect(html).not.toContain('name="action" value="start"');
		expect(linkMailsTo(email)).toHaveLength(0);
	});

	for (const [what, setup] of [
		[
			'the project does not let people do it',
			() => project({ totpSelfService: false })
		],
		['password sign-in is off', () => project({ passwordLogin: false })],
		['mail cannot be sent', () => mailOn(false)]
	] as const) {
		it(`offers nothing when ${what}`, async () => {
			const { browser, email } = await signedIn();
			await setup();

			const html = await (await browser.request(PAGE)).text();
			await start(browser);

			expect(html).not.toContain('name="action" value="start"');
			expect(linkMailsTo(email)).toHaveLength(0);
		});
	}

	it('shows no secret before the mailed link is followed', async () => {
		const { browser } = await signedIn();

		await start(browser);
		const { html } = await openPage(browser, '?sent=enrol');

		expect(html).not.toContain('data-key=');
		expect(html).not.toContain('otpauth://');
	});

	it('does nothing with the link in another browser, and still works in the one that asked', async () => {
		const { browser, email } = await signedIn();
		await start(browser);
		const link = linkIn(email, LINK_PATH);
		const other = new Browser();
		await signInThroughPage(other, email);

		await other.open(link);
		const elsewhere = await openPage(other);
		await browser.open(link);
		const here = await openPage(browser);

		expect(elsewhere.html).not.toContain('data-key=');
		expect(here.html).toContain('data-key=');
	});

	it('does nothing with a link older than ten minutes', async () => {
		const { browser, email } = await signedIn();
		await start(browser);
		setSystemTime(new Date(Date.now() + 11 * 60 * 1000));

		await browser.open(linkIn(email, LINK_PATH));
		const { html } = await openPage(browser);

		expect(html).not.toContain('data-key=');
	});

	it('does nothing with a link already used', async () => {
		const { browser, email } = await signedIn();
		await start(browser);
		const link = linkIn(email, LINK_PATH);
		const { key, xsrf } = await startAndFollowOnce(browser, link);
		await browser.post(PAGE, { action: 'confirm', xsrf, code: codeFor(key) });

		const again = await browser.open(link);

		expect(again.url).toContain('notice=link');
	});

	it('does nothing with a link once a newer one was sent', async () => {
		const { browser, email } = await signedIn();
		await start(browser);
		const older = linkIn(email, LINK_PATH);
		setSystemTime(new Date(Date.now() + 61 * 1000));
		await start(browser);

		await browser.open(older);
		const { html } = await openPage(browser);

		expect(html).not.toContain('data-key=');
	});

	it('sends at most five links a day to one account', async () => {
		const { browser, email } = await signedIn();
		let at = Date.now();
		for (let sent = 0; sent < 6; sent++) {
			setSystemTime(new Date(at));
			await freshen(browser);
			await start(browser);
			at += 61 * 1000;
		}

		expect(linkMailsTo(email)).toHaveLength(5);
	});

	it('does not finish once the project stopped letting people do it', async () => {
		const { browser, email, accountId } = await signedIn();
		const { key, xsrf } = await startAndFollow(browser, email);
		await project({ totpSelfService: false });

		await browser.post(PAGE, { action: 'confirm', xsrf, code: codeFor(key) });

		expect(
			(await getUserStore(DEFAULT_BUCKET_ID).find(accountId))?.totp
		).toBeUndefined();
	});

	it('ends the offer after five wrong codes', async () => {
		const { browser, email, accountId } = await signedIn();
		const { key, xsrf } = await startAndFollow(browser, email);
		const right = codeFor(key);
		const wrong = right === '000000' ? '111111' : '000000';
		for (let i = 0; i < 5; i++) {
			await browser.post(PAGE, { action: 'confirm', xsrf, code: wrong });
		}

		await browser.post(PAGE, { action: 'confirm', xsrf, code: right });

		expect(
			(await getUserStore(DEFAULT_BUCKET_ID).find(accountId))?.totp
		).toBeUndefined();
	});

	it('does not let the code that completed the enrolment sign in', async () => {
		const { browser, email, accountId } = await signedIn();
		const key = await enrol(browser, email);

		const outcome = await verifyForAccount(
			DEFAULT_BUCKET_ID,
			accountId,
			codeFor(key)
		);

		expect(outcome.ok).toBe(false);
	});

	it('never writes the secret, the link or the code to the audit trail or the log', async () => {
		const logged: string[] = [];
		const spies = (['log', 'info', 'warn', 'error'] as const).map((level) =>
			spyOn(console, level).mockImplementation((...args: unknown[]) => {
				logged.push(JSON.stringify(args));
			})
		);
		try {
			const { browser, email, accountId } = await signedIn();
			const key = await enrol(browser, email);
			const token = new URL(
				linkIn(email, '/account/security/disown')
			).searchParams.get('token');

			const trail = JSON.stringify(
				(await adminAuditStore.list({ targetId: accountId })).entries
			);
			for (const secret of [key, present(token, 'a token')]) {
				expect(trail).not.toContain(secret);
				expect(logged.join('\n')).not.toContain(secret);
			}
		} finally {
			spies.forEach((spy) => spy.mockRestore());
		}
	});
});

/* Follows one given link in this browser and answers what the page then offers. */
async function startAndFollowOnce(
	browser: Browser,
	link: string
): Promise<{ key: string; xsrf: string }> {
	await browser.open(link);
	const offered = await openPage(browser);
	return { key: keyFrom(offered.html), xsrf: offered.xsrf };
}
