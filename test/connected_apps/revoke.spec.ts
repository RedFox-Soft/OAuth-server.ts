import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap, { encodeParams } from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { getBucketStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ACCOUNT_PAGE_TEXTS as T } from 'lib/account_page/texts.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { mock as mockHttp } from '../fetch_mock.js';
import { createAdministrator } from '../administrators.ts';
import { cookieFor, regularGroup } from '../admin/ownership_fixtures.ts';
import { present } from '../shape.ts';
import {
	auditOf,
	Browser,
	defaultBucket,
	giveAccess,
	introspect,
	openConfirmation,
	pageOf,
	person,
	refresh,
	signInThroughPage,
	textOf,
	xsrfFrom
} from './helpers.ts';

interface Signed {
	browser: Browser;
	accountId: string;
	email: string;
}

async function signedIn(): Promise<Signed> {
	const { email, accountId } = await person();
	const browser = new Browser();
	await signInThroughPage(browser, email);
	return { browser, accountId, email };
}

/* Confirms the removal the way the confirmation page's form does. */
async function remove(browser: Browser, clientId: string): Promise<Response> {
	const { html } = await openConfirmation(browser, clientId);
	return browser.post(pageOf(), { clientId, xsrf: xsrfFrom(html) });
}

/**
 * @proves A person removes one application's access from their page: it loses every token and its part of
 * the sign-in, is told when it asked to be, must ask again next time, and everything else the person allowed
 * carries on — and the removal is on the record, readable by the bucket's own administrators.
 */
describe('removing an application’s access', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'connected_apps' });
		await ensureAdminSeed();
		await defaultBucket();
	});

	afterEach(() => {
		mockHttp.restore();
	});

	it('asks first, naming the application and what will happen', async () => {
		const { browser } = await signedIn();
		await giveAccess(browser, 'offline-app', 'openid offline_access');

		const { response, html } = await openConfirmation(browser, 'offline-app');

		expect(response.status).toBe(200);
		const text = textOf(html);
		expect(text).toContain(T.confirmTitle('Mail Sync'));
		expect(text).toContain(T.confirmEffect('Mail Sync'));
		expect(text).toContain(T.confirmAsksAgain);
		expect(html).toContain('<form method="post" action="/account/apps"');
		expect(html).toContain('name="clientId" value="offline-app"');
	});

	it('ends the application’s refresh and access tokens and leaves the other application’s working', async () => {
		const { browser } = await signedIn();
		const removed = await giveAccess(
			browser,
			'offline-app',
			'openid offline_access'
		);
		const kept = await giveAccess(browser, 'own-app', 'openid offline_access');

		const res = await remove(browser, 'offline-app');

		expect(res.status).toBe(303);
		expect(res.headers.get('location')).toBe('/account/apps?done=offline-app');
		const refused = await refresh(
			'offline-app',
			present(removed.refreshToken, 'a refresh token')
		);
		expect(refused.error?.value).toMatchObject({ error: 'invalid_grant' });
		expect(await introspect(removed.accessToken)).toEqual({ active: false });
		const still = await refresh(
			'own-app',
			present(kept.refreshToken, 'a refresh token')
		);
		expect(still.status).toBe(200);
	});

	it('says access was removed and no longer lists the application, with the person still signed in', async () => {
		const { browser } = await signedIn();
		await giveAccess(browser, 'offline-app', 'openid offline_access');
		await giveAccess(browser, 'own-app', 'openid email');
		const res = await remove(browser, 'offline-app');

		const after = await browser.request(
			present(res.headers.get('location'), 'a location')
		);

		expect(after.status).toBe(200);
		const text = textOf(await after.text());
		expect(text).toContain(T.done('Mail Sync'));
		expect(text).toContain('Timesheets');
		expect(text).not.toContain(T.confirmTitle('Mail Sync'));
		expect(text.match(/Mail Sync/g)?.length).toBe(1);
	});

	it('asks for consent again the next time the application signs the person in', async () => {
		const { browser } = await signedIn();
		await giveAccess(browser, 'own-app', 'openid email');
		await remove(browser, 'own-app');

		const auth = new AuthorizationRequest({
			client_id: 'own-app',
			scope: 'openid email'
		});
		const next = await browser.open(`/auth?${encodeParams(auth.params)}`);

		expect(next.url).toMatch(/\/ui\/[^/]+\/consent$/);
	});

	it('tells the application its sign-in ended when back-channel logout is on', async () => {
		const { browser } = await signedIn();
		await giveAccess(browser, 'offline-app', 'openid offline_access');
		let told = false;
		mockHttp('https://mail.acme.test')
			.intercept({
				path: '/backchannel_logout',
				method: 'POST',
				body() {
					told = true;
					return true;
				}
			})
			.reply(200);

		await remove(browser, 'offline-app');

		expect(told).toBe(true);
	});

	it('warns that an application of the organization that never asks will sign the person in again, and ends its tokens', async () => {
		const { browser } = await signedIn();
		const access = await giveAccess(browser, 'waived-app');

		const { html } = await openConfirmation(browser, 'waived-app');
		await browser.post(pageOf(), {
			clientId: 'waived-app',
			xsrf: xsrfFrom(html)
		});

		expect(textOf(html)).toContain(T.confirmReturnsSilently);
		expect(await introspect(access.accessToken)).toEqual({ active: false });
	});

	it('removes from the page’s own form as a browser sends it under the server’s no-referrer policy', async () => {
		const { browser } = await signedIn();
		const access = await giveAccess(browser, 'own-app', 'openid email');
		const { html } = await openConfirmation(browser, 'own-app');

		/* `Referrer-Policy: no-referrer` makes a browser serialize even a same-origin form's origin as "null". */
		const res = await browser.post(
			pageOf(),
			{ clientId: 'own-app', xsrf: xsrfFrom(html) },
			{ origin: 'null', 'sec-fetch-site': 'same-origin' }
		);

		expect(res.headers.get('location')).toBe('/account/apps?done=own-app');
		expect(await introspect(access.accessToken)).toEqual({ active: false });
	});

	it('answers that the application no longer has access when it was already removed', async () => {
		const { browser } = await signedIn();
		await giveAccess(browser, 'own-app', 'openid email');
		const { html } = await openConfirmation(browser, 'own-app');
		await browser.post(pageOf(), { clientId: 'own-app', xsrf: xsrfFrom(html) });

		const again = await browser.post(pageOf(), {
			clientId: 'own-app',
			xsrf: xsrfFrom(html)
		});

		expect(again.status).toBe(303);
		expect(again.headers.get('location')).toBe('/account/apps?gone=1');
	});

	it('changes nothing when the person cancels', async () => {
		const { browser } = await signedIn();
		const access = await giveAccess(browser, 'own-app', 'openid email');
		const { html } = await openConfirmation(browser, 'own-app');
		const cancel = present(
			/<a href="([^"]+)"[^>]*>Cancel<\/a>/.exec(html)?.[1],
			'a cancel link'
		);

		const back = await browser.request(cancel);

		expect(textOf(await back.text())).toContain('Timesheets');
		expect(await introspect(access.accessToken)).toMatchObject({
			active: true
		});
	});

	it('records the removal once, with the person as actor', async () => {
		const { browser, accountId } = await signedIn();
		await giveAccess(browser, 'own-app', 'openid email');

		await remove(browser, 'own-app');

		const entries = await auditOf(accountId);
		expect(entries).toHaveLength(1);
		const bucket = present(
			await getBucketStore().find(DEFAULT_BUCKET_ID),
			'the bucket'
		);
		expect(entries[0]).toMatchObject({
			action: 'enduser.application.signout',
			actorId: `enduser:${DEFAULT_BUCKET_ID}:${accountId}`,
			viaSurface: 'self-service',
			targetId: accountId,
			targetScope: DEFAULT_BUCKET_ID,
			clientId: 'own-app',
			ownerGroupId: bucket.ownerGroupId
		});
	});

	it('records nothing when nothing was removed', async () => {
		const { browser, accountId } = await signedIn();
		await giveAccess(browser, 'own-app', 'openid email');
		const { html } = await openConfirmation(browser, 'own-app');

		await browser.post(pageOf(), {
			clientId: 'offline-app',
			xsrf: xsrfFrom(html)
		});

		expect(await auditOf(accountId)).toHaveLength(0);
	});

	it('lets an administrator of the group owning the bucket read the record', async () => {
		const admin = await createAdministrator(
			'plain',
			`admin-${Math.random()}@x.io`
		);
		const group = await regularGroup([admin]);
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			ownerGroupId: group._id
		});
		const { browser, accountId, email } = await signedIn();
		await giveAccess(browser, 'own-app', 'openid email');
		await remove(browser, 'own-app');

		const res = await elysia.handle(
			new Request(
				`${ISSUER}/admin/api/audit?targetId=${accountId}&targetScope=${DEFAULT_BUCKET_ID}`,
				{ headers: { cookie: await cookieFor(admin) } }
			)
		);

		expect(res.status).toBe(200);
		const page = (await res.json()) as {
			entries: Array<{ actorName?: string }>;
		};
		expect(page.entries).toHaveLength(1);
		expect(page.entries[0]?.actorName).toBe(email);
	});
});
