import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap from '../test_helper.js';
import {
	adminAuditStore,
	getBucketStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { configuration } from 'lib/configs/application.ts';
import { sessionCookieName } from 'lib/consts/param_list.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { Session } from 'lib/models/session.ts';
import { verifyForAccount } from 'lib/totp/verify.ts';
import { present } from '../shape.ts';
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
	project,
	signedIn
} from './helpers.ts';

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

async function rewriteSession(
	browser: Browser,
	change: Partial<Session['payload']>
): Promise<void> {
	const session = await sessionOf(browser);
	Object.assign(session.payload, change);
	await session.save(
		(session.payload.exp ?? 0) - Math.floor(Date.now() / 1000)
	);
}

async function act(browser: Browser, action: string): Promise<Response> {
	const xsrf = present(
		(await sessionOf(browser)).payload.accountPageXsrf,
		'the anti-forgery value'
	);
	return browser.post(PAGE, { action, xsrf });
}

function isSignInRedirect(res: Response): boolean {
	return (
		res.status === 303 &&
		new URL(res.headers.get('location') ?? '', 'http://x').pathname === '/auth'
	);
}

async function enrolled() {
	const signed = await signedIn();
	const key = await enrol(signed.browser, signed.email);
	return { ...signed, key };
}

/**
 * @proves A person who entered a code from their authenticator app moments ago can move two-step verification to a
 * new phone or turn it off; without such a code, a password or a provider sign-in alone changes nothing.
 */
describe('changing or turning off your own two-step verification', () => {
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
		await project();
	});

	it('moves it to a new phone: the new code signs in, the old one no longer does', async () => {
		const { browser, email, accountId, key: oldKey } = await enrolled();
		// A minute after the enrolment's own link: links to one account go at most one a minute.
		setSystemTime(new Date(Date.now() + 61 * 1000));

		const asked = await act(browser, 'replace');
		expect(asked.headers.get('location')).toContain('sent=replace');
		await browser.open(linkIn(email, '/account/security/link'));
		const offered = await openPage(browser);
		const newKey = keyFrom(offered.html);
		const done = await browser.post(PAGE, {
			action: 'confirm',
			xsrf: offered.xsrf,
			code: codeFor(newKey)
		});
		expect(done.headers.get('location')).toContain('done=changed');

		setSystemTime(new Date(Date.now() + 31 * 1000));
		expect(
			(await verifyForAccount(DEFAULT_BUCKET_ID, accountId, codeFor(oldKey))).ok
		).toBe(false);
		expect(
			(await verifyForAccount(DEFAULT_BUCKET_ID, accountId, codeFor(newKey))).ok
		).toBe(true);
		expect(mailsTo(email).map((mail) => mail.subject)).toContain(
			'Two-step verification was moved to a different phone'
		);
		const { entries } = await adminAuditStore.list({ targetId: accountId });
		expect(entries.map((entry) => entry.action)).toContain(
			'enduser.totp.replace'
		);
	});

	it('turns it off after a confirmation, and says so by mail', async () => {
		const { browser, email, accountId } = await enrolled();

		const confirmation = await openPage(browser, '?off=1');
		expect(confirmation.html).toContain('name="action" value="off"');
		const done = await act(browser, 'off');

		expect(done.headers.get('location')).toContain('done=off');
		expect(
			(await getUserStore(DEFAULT_BUCKET_ID).find(accountId))?.totp
		).toBeUndefined();
		expect(mailsTo(email).map((mail) => mail.subject)).toContain(
			'Two-step verification was turned off for your default account'
		);
		const { entries } = await adminAuditStore.list({ targetId: accountId });
		expect(entries.map((entry) => entry.action)).toContain(
			'enduser.totp.remove'
		);
	});

	for (const [what, change] of [
		[
			'a password-only session',
			{ amr: ['pwd'], acr: configuration.acrMap.password }
		],
		['a provider sign-in', { amr: [], acr: configuration.acrMap.federated }]
	] as const) {
		it(`asks for a sign-in with the code first on ${what}, and changes nothing`, async () => {
			const { browser, accountId } = await enrolled();
			await rewriteSession(browser, {
				amr: [...change.amr],
				acr: change.acr
			});
			const before = (await getUserStore(DEFAULT_BUCKET_ID).find(accountId))
				?.totp?.secret;

			expect(isSignInRedirect(await act(browser, 'replace'))).toBe(true);
			expect(isSignInRedirect(await act(browser, 'off'))).toBe(true);
			expect(
				(await getUserStore(DEFAULT_BUCKET_ID).find(accountId))?.totp?.secret
			).toBe(before);
		});
	}

	it('asks for a sign-in with the code first when the code is older than fifteen minutes', async () => {
		const { browser, accountId } = await enrolled();
		setSystemTime(new Date(Date.now() + 16 * 60 * 1000));

		expect(isSignInRedirect(await act(browser, 'off'))).toBe(true);
		expect(
			(await getUserStore(DEFAULT_BUCKET_ID).find(accountId))?.totp
		).toBeDefined();
	});

	it('does not offer or allow turning it off in a project that requires it', async () => {
		const { browser, accountId } = await enrolled();
		await project({ totpRequired: true });

		const { html } = await openPage(browser);
		await act(browser, 'off');

		expect(html).not.toContain('?off=1');
		expect(
			(await getUserStore(DEFAULT_BUCKET_ID).find(accountId))?.totp
		).toBeDefined();
	});

	it('writes nothing when the factor changed while the replacement was under way', async () => {
		const { browser, email, accountId } = await enrolled();
		setSystemTime(new Date(Date.now() + 61 * 1000));
		await act(browser, 'replace');
		await browser.open(linkIn(email, '/account/security/link'));
		const offered = await openPage(browser);
		const meanwhile = {
			secret: 'JBSWY3DPEHPK3PXP',
			enrolledAt: new Date(Date.now() + 1000),
			lastStep: 0,
			via: 'sign-in' as const
		};
		await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
			totp: meanwhile
		});

		const done = await browser.post(PAGE, {
			action: 'confirm',
			xsrf: offered.xsrf,
			code: codeFor(keyFrom(offered.html))
		});

		expect(done.headers.get('location')).toContain('notice=changed');
		expect(
			(await getUserStore(DEFAULT_BUCKET_ID).find(accountId))?.totp?.secret
		).toBe(meanwhile.secret);
	});
});
