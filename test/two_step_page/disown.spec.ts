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
import { sessionCookieName } from 'lib/consts/param_list.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { Session } from 'lib/models/session.ts';
import { present } from '../shape.ts';
import {
	Browser,
	codeFor,
	enrol,
	keyFrom,
	linkIn,
	mailOn,
	openPage,
	PAGE,
	project,
	signedIn
} from './helpers.ts';

const DISOWN = '/account/security/disown';

async function factorOf(accountId: string) {
	return (await getUserStore(DEFAULT_BUCKET_ID).find(accountId))?.totp;
}

async function sessionId(browser: Browser): Promise<string> {
	const bucket = present(
		await getBucketStore().find(DEFAULT_BUCKET_ID),
		'the bucket'
	);
	const name = sessionCookieName(bucket);
	return present(
		browser.cookie
			.split('; ')
			.find((pair) => pair.startsWith(`${name}=`))
			?.slice(name.length + 1),
		'a session cookie'
	);
}

/* What the owner does from the mail: open the link, then confirm on the page it shows. */
async function disown(link: string, headers: Record<string, string> = {}) {
	const owner = new Browser();
	const page = await owner.request(link);
	const token = present(new URL(link).searchParams.get('token'), 'a token');
	const answer = await owner.post(DISOWN, { token }, headers);
	return { page, answer };
}

/**
 * @proves The owner of an account gets it back on their own when someone else turned on two-step verification with
 * their password and mailbox: the link in the mail removes that factor and signs the account out everywhere, within
 * three days and only for that same factor.
 */
describe('"This wasn’t me" after two-step verification was turned on', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		await project();
	});

	afterEach(() => {
		setSystemTime();
	});

	it('removes the factor and signs the account out everywhere', async () => {
		const { browser, email, accountId } = await signedIn();
		await enrol(browser, email);
		const session = await sessionId(browser);

		const { page, answer } = await disown(linkIn(email, DISOWN));

		expect(await page.text()).toContain('name="token"');
		expect(answer.status).toBe(200);
		expect(await factorOf(accountId)).toBeUndefined();
		expect(await Session.tryFind(session)).toBeUndefined();
		const { entries } = await adminAuditStore.list({ targetId: accountId });
		expect(entries.map((entry) => entry.action)).toContain(
			'enduser.totp.disown'
		);
	});

	it('changes nothing when only the link is opened', async () => {
		const { browser, email, accountId } = await signedIn();
		await enrol(browser, email);

		await new Browser().request(linkIn(email, DISOWN));

		expect(await factorOf(accountId)).toBeDefined();
	});

	it('changes nothing after 72 hours', async () => {
		const { browser, email, accountId } = await signedIn();
		await enrol(browser, email);
		const link = linkIn(email, DISOWN);
		setSystemTime(new Date(Date.now() + 73 * 60 * 60 * 1000));

		const { answer } = await disown(link);

		expect(answer.status).toBe(400);
		expect(await factorOf(accountId)).toBeDefined();
	});

	it('changes nothing for a factor that replaced the one the mail was about', async () => {
		const { browser, email, accountId } = await signedIn();
		await enrol(browser, email);
		const first = linkIn(email, DISOWN);
		setSystemTime(new Date(Date.now() + 61 * 1000));
		const { xsrf } = await openPage(browser);
		await browser.post(PAGE, { action: 'replace', xsrf });
		await browser.open(linkIn(email, '/account/security/link'));
		const offered = await openPage(browser);
		await browser.post(PAGE, {
			action: 'confirm',
			xsrf: offered.xsrf,
			code: codeFor(keyFrom(offered.html))
		});
		const replaced = await factorOf(accountId);

		await disown(first);

		expect((await factorOf(accountId))?.secret).toBe(replaced?.secret);
	});

	it('changes nothing the second time', async () => {
		const { browser, email, accountId } = await signedIn();
		await enrol(browser, email);
		const link = linkIn(email, DISOWN);
		await disown(link);
		await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
			totp: {
				secret: 'JBSWY3DPEHPK3PXP',
				enrolledAt: new Date(),
				lastStep: 0,
				via: 'self'
			}
		});

		const { answer } = await disown(link);

		expect(answer.status).toBe(400);
		expect(await factorOf(accountId)).toBeDefined();
	});

	// Found by the browser walk: the outcome came back in the browser's language after a confirmation in theirs.
	it('answers in the person’s own language', async () => {
		const { browser, email, accountId } = await signedIn();
		await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
			profile: { locale: 'ru' }
		});
		await enrol(browser, email);

		const { answer } = await disown(linkIn(email, DISOWN));

		expect(answer.headers.get('content-language')).toBe('ru');
	});

	it('refuses a confirmation another site sent', async () => {
		const { browser, email, accountId } = await signedIn();
		await enrol(browser, email);

		const { answer } = await disown(linkIn(email, DISOWN), {
			'sec-fetch-site': 'cross-site'
		});

		expect(answer.status).toBe(403);
		expect(await factorOf(accountId)).toBeDefined();
	});
});
