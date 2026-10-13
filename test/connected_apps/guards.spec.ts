import {
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap, { encodeParams } from '../test_helper.js';
import {
	getBucketStore,
	getProjectStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ACCOUNT_PAGE_COOKIE } from 'lib/consts/account_page.ts';
import { ACCOUNT_PAGE_TEXTS as T } from 'lib/account_page/texts.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { present } from '../shape.ts';
import {
	addressedBucket,
	Browser,
	defaultBucket,
	giveAccess,
	introspect,
	openConfirmation,
	pageOf,
	PASSWORD,
	person,
	signInThroughPage,
	textOf,
	xsrfFrom
} from './helpers.ts';

interface Signed {
	browser: Browser;
	accountId: string;
	email: string;
}

async function signedIn(bucketId?: string, prefix = ''): Promise<Signed> {
	const { email, accountId } = await person(bucketId);
	const browser = new Browser();
	await signInThroughPage(browser, email, prefix);
	return { browser, accountId, email };
}

function isSignInRedirect(res: Response, path = '/auth'): boolean {
	return (
		res.status === 303 &&
		new URL(res.headers.get('location') ?? '', 'http://x').pathname.endsWith(
			path
		)
	);
}

/* The pending sign-in cookie as the page writes it: base64url JSON. */
function pending(value: Record<string, unknown>): string {
	return Buffer.from(JSON.stringify(value)).toString('base64url');
}

/**
 * @proves The page shows and changes only the access of the person signed in to that bucket: nobody else's,
 * no other bucket's, never for a person who may not sign in, never on a request another site sent or a stale
 * sign-in, and the administrators' bucket has no such page at all.
 */
describe('who may see and change access on the page', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'connected_apps' });
		await ensureAdminSeed();
		await defaultBucket();
		await addressedBucket('acme-bucket', { slug: 'acme' });
	});

	afterEach(() => {
		setSystemTime();
	});

	it('starts a sign-in rather than showing anything at a bucket the session does not belong to', async () => {
		const { browser } = await signedIn('acme-bucket', '/acme');

		const res = await browser.request(pageOf());

		expect(isSignInRedirect(res)).toBe(true);
	});

	it('keeps two buckets’ people apart when they hold the same account id', async () => {
		const { email: rootEmail } = await person(undefined, { id: 'shared-id' });
		const root = new Browser();
		await signInThroughPage(root, rootEmail);
		await giveAccess(root, 'own-app', 'openid email');
		const { email: acmeEmail } = await person('acme-bucket', {
			id: 'shared-id'
		});
		const acme = new Browser();

		const landed = await signInThroughPage(acme, acmeEmail, '/acme');

		const text = textOf(await landed.text());
		expect(text).toContain(T.empty);
		expect(text).not.toContain('Timesheets');
	});

	it('shows nothing to a deactivated person whose session is replayed, and removes nothing for them', async () => {
		const { browser, accountId } = await signedIn();
		const access = await giveAccess(browser, 'own-app', 'openid email');
		const { html } = await openConfirmation(browser, 'own-app');
		await getUserStore().update(accountId, { active: false });

		const page = await browser.request(pageOf());
		const removal = await browser.post(pageOf(), {
			clientId: 'own-app',
			xsrf: xsrfFrom(html)
		});

		expect(isSignInRedirect(page)).toBe(true);
		expect(isSignInRedirect(removal)).toBe(true);
		expect(await introspect(access.accessToken)).toMatchObject({
			active: true
		});
	});

	it('shows nothing to a person locked by an administrator', async () => {
		const { browser, accountId } = await signedIn();
		await getUserStore().update(accountId, {
			lockedLocally: {
				at: new Date(),
				reason: 'reported stolen',
				by: 'an-admin'
			}
		});

		const page = await browser.request(pageOf());

		expect(isSignInRedirect(page)).toBe(true);
	});

	describe('a removal not sent by the page', () => {
		async function prepared() {
			const signed = await signedIn();
			const access = await giveAccess(
				signed.browser,
				'own-app',
				'openid email'
			);
			const { html } = await openConfirmation(signed.browser, 'own-app');
			return { ...signed, access, xsrf: xsrfFrom(html) };
		}

		it('is refused when another site sent it', async () => {
			const { browser, access, xsrf } = await prepared();

			const res = await browser.post(
				pageOf(),
				{ clientId: 'own-app', xsrf },
				{ origin: 'https://evil.example' }
			);

			expect(res.status).toBe(403);
			expect(await introspect(access.accessToken)).toMatchObject({
				active: true
			});
		});

		it('is refused when the browser says it came from another site', async () => {
			const { browser, access, xsrf } = await prepared();

			const res = await browser.post(
				pageOf(),
				{ clientId: 'own-app', xsrf },
				{ 'sec-fetch-site': 'cross-site' }
			);

			expect(res.status).toBe(403);
			expect(await introspect(access.accessToken)).toMatchObject({
				active: true
			});
		});

		it('is refused without the page’s anti-forgery value', async () => {
			const { browser, access } = await prepared();

			const res = await browser.post(pageOf(), { clientId: 'own-app' });

			expect(res.status).toBe(403);
			expect(await introspect(access.accessToken)).toMatchObject({
				active: true
			});
		});

		it('is refused with another session’s anti-forgery value', async () => {
			const { browser, access } = await prepared();
			const other = await prepared();

			const res = await browser.post(pageOf(), {
				clientId: 'own-app',
				xsrf: other.xsrf
			});

			expect(res.status).toBe(403);
			expect(await introspect(access.accessToken)).toMatchObject({
				active: true
			});
		});
	});

	it('changes nothing for another person’s application, answering as for one that does not exist', async () => {
		const owner = await signedIn();
		const theirs = await giveAccess(owner.browser, 'own-app', 'openid email');
		const intruder = await signedIn();
		await giveAccess(intruder.browser, 'waived-app');
		const { html } = await openConfirmation(intruder.browser, 'waived-app');
		const xsrf = xsrfFrom(html);

		const foreign = await intruder.browser.post(pageOf(), {
			clientId: 'own-app',
			xsrf
		});
		const unknown = await intruder.browser.post(pageOf(), {
			clientId: 'no-such-app',
			xsrf
		});

		expect(foreign.headers.get('location')).toBe('/account/apps?gone=1');
		expect(unknown.headers.get('location')).toBe('/account/apps?gone=1');
		expect(await introspect(theirs.accessToken)).toMatchObject({
			active: true
		});
	});

	it('does not offer or remove the page’s own sign-in', async () => {
		const { browser } = await signedIn();
		await giveAccess(browser, 'waived-app');
		const { html } = await openConfirmation(browser, 'waived-app');

		const res = await browser.post(pageOf(), {
			clientId: 'account.redfox',
			xsrf: xsrfFrom(html)
		});

		expect(res.headers.get('location')).toBe('/account/apps?gone=1');
		expect(textOf(await (await browser.request(pageOf())).text())).toContain(
			T.title
		);
	});

	it('asks for the sign-in again when it is older than fifteen minutes, and removes nothing until confirmed', async () => {
		const { browser, email } = await signedIn();
		const access = await giveAccess(browser, 'own-app', 'openid email');
		const { html } = await openConfirmation(browser, 'own-app');
		setSystemTime(new Date(Date.now() + 16 * 60 * 1000));

		const stale = await browser.post(pageOf(), {
			clientId: 'own-app',
			xsrf: xsrfFrom(html)
		});

		expect(isSignInRedirect(stale)).toBe(true);
		const location = new URL(
			present(stale.headers.get('location'), 'a location')
		);
		expect(location.searchParams.get('prompt')).toBe('login');
		expect(await introspect(access.accessToken)).toMatchObject({
			active: true
		});

		const login = await browser.open(location.toString());
		const posted = await browser.request(login.url, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				username: email,
				password: PASSWORD
			}).toString()
		});
		const back = await browser.open(
			new URL(
				present(posted.headers.get('location'), 'a resume'),
				login.url
			).toString()
		);
		expect(back.url).toMatch(/\/account\/apps\?revoke=own-app$/);
		expect(textOf(await back.response.text())).toContain(
			T.confirmTitle('Timesheets')
		);
		expect(await introspect(access.accessToken)).toMatchObject({
			active: true
		});
	});

	it('drops what was asked when a different person finishes the sign-in', async () => {
		const { accountId } = await signedIn();
		const someoneElse = await person();
		const cookieBrowser = new Browser();
		await signInThroughPage(cookieBrowser, someoneElse.email);
		await cookieBrowser.request(pageOf());
		const jarWithPending = `${cookieBrowser.cookie}; ${ACCOUNT_PAGE_COOKIE}=${pending(
			{
				state: 'the-state',
				startedAt: 0,
				accountId,
				revoke: 'own-app'
			}
		)}`;

		const res = await cookieBrowser.request(
			`${pageOf()}/callback?state=the-state`,
			{
				headers: { cookie: jarWithPending }
			}
		);

		expect(res.status).toBe(303);
		expect(res.headers.get('location')).toBe('/account/apps');
	});

	it('has no page for the administrators’ bucket and starts no sign-in for one', async () => {
		const browser = new Browser();

		const res = await browser.request(pageOf('/admin'));

		/* The console owns every /admin address; whatever it answers, it is not this page. */
		expect(res.status).not.toBe(200);
		expect(res.headers.get('location') ?? '').not.toContain('account.');
	});

	describe('a bucket with no address of its own', () => {
		it('shows the person signed in to it at the root their own applications', async () => {
			const bucket = await getBucketStore().create({
				_id: 'loose-bucket',
				name: 'loose people',
				ownerGroupId: UNASSIGNED_GROUP_ID
			});
			const project = await getProjectStore().create({
				name: 'loose',
				slug: `loose-${Math.random()}`,
				ownerGroupId: UNASSIGNED_GROUP_ID
			});
			await getProjectStore().update(project._id, {
				bucketId: bucket._id,
				clientIds: ['loose-app']
			});
			const { email } = await person('loose-bucket');
			const browser = new Browser();
			const auth = new AuthorizationRequest({
				client_id: 'loose-app',
				scope: 'openid'
			});
			const login = await browser.open(`/auth?${encodeParams(auth.params)}`);
			const posted = await browser.request(login.url, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					username: email,
					password: PASSWORD
				}).toString()
			});
			await browser.open(
				new URL(
					present(posted.headers.get('location'), 'a resume'),
					login.url
				).toString()
			);

			const page = await browser.request(pageOf());

			expect(page.status).toBe(200);
			const text = textOf(await page.text());
			expect(text).toContain(email);
			expect(text).toContain('Loose Tool');

			forgetBucketAddresses();
			await getBucketStore().update('loose-bucket', { slug: 'loose' });
			forgetBucketAddresses();

			const moved = await browser.request(pageOf());

			expect(isSignInRedirect(moved)).toBe(true);
		});
	});
});
