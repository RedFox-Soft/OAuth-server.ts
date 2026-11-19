import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';

import bootstrap, { bindClientToBucket } from '../test_helper.js';
import {
	getBucketStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { namespaceOf } from 'lib/resources/namespace.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { present } from '../shape.ts';
import {
	ACME,
	Browser,
	PASSWORD,
	claimsOf,
	codeAfter,
	holdingPasskey,
	mailOn,
	person,
	postPasskey,
	project,
	propsIn,
	redeem,
	signInPage,
	signInWithPasskey,
	textOf,
	type Project
} from './helpers.ts';

let acme: Project;
let billing: Project;

const MULTI_FACTOR = 'urn:example:acr:mfa';
const FILES = 'https://files.acme.test/mcp';

/* The app that requires two-step sign-in, signed in to with a password alone: where that sign-in stops. */
async function codeRequiredPage(
	email: string
): Promise<{ browser: Browser; auth: AuthorizationRequest; html: string }> {
	const browser = new Browser(acme.origin);
	const { auth, url } = await signInPage(browser, billing);
	const posted = await browser.post(url, {
		username: email,
		password: PASSWORD
	});
	const reached = await browser.open(
		new URL(
			present(posted.headers.get('location'), 'a redirect'),
			url
		).toString()
	);
	expect(reached.url).toMatch(/\/ui\/[^/]+\/code-required$/);
	return { browser, auth, html: await reached.response.text() };
}

/**
 * @proves A passkey sign-in meets every requirement of two-step sign-in with no code asked: an app's own, an API's,
 * and a relying party's essential request for the multi-factor context; and the page that stops a password sign-in
 * at an app requiring two-step sign-in offers the passkey sign-in that lets the person through.
 */
describe('requirements of two-step sign-in, met by a passkey', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		acme = await project(ACME);
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
		billing = { ...acme, clientId: 'acme-billing' };
		await bindClientToBucket(billing.clientId, acme.bucketId);
		const bucket = present(
			await getBucketStore().find(acme.bucketId),
			'the project'
		);
		await getProtectedResourceStore().create({
			namespace: namespaceOf(bucket),
			identifier: FILES,
			bucketId: acme.bucketId,
			name: 'Files',
			scopes: ['files:read'],
			tokenFormat: 'jwt',
			requireCode: true
		});
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
	});

	it('meets an app’s own requirement of two-step sign-in', async () => {
		const { device } = await holdingPasskey(acme);

		const { auth, code } = await signInWithPasskey(
			new Browser(acme.origin),
			device,
			billing
		);

		expect(claimsOf((await redeem(billing, auth, code)).id_token).acr).toBe(
			MULTI_FACTOR
		);
	});

	it('meets an API’s requirement of two-step sign-in', async () => {
		const { device } = await holdingPasskey(acme);

		const { auth, code } = await signInWithPasskey(
			new Browser(acme.origin),
			device,
			acme,
			{ scope: 'openid files:read', resource: FILES }
		);

		const { access_token } = await redeem(acme, auth, code, {
			resource: FILES
		});
		expect(claimsOf(access_token)).toMatchObject({
			aud: FILES,
			acr: MULTI_FACTOR
		});
	});

	it('meets an essential request for the multi-factor context', async () => {
		const { device } = await holdingPasskey(acme);

		const { auth, code } = await signInWithPasskey(
			new Browser(acme.origin),
			device,
			acme,
			{
				claims: JSON.stringify({
					id_token: { acr: { essential: true, values: [MULTI_FACTOR] } }
				})
			}
		);

		expect(claimsOf((await redeem(acme, auth, code)).id_token).acr).toBe(
			MULTI_FACTOR
		);
	});

	it('offers first, on the page that stops a password sign-in, the passkey the person holds', async () => {
		const { email } = await holdingPasskey(acme);

		const { html } = await codeRequiredPage(email);

		expect(propsIn(html)).toMatchObject({ passkey: 'primary' });
		expect(textOf(html)).toContain(
			`You have a passkey for ${email}. Sign in with it to continue.`
		);
	});

	it('offers a passkey sign-in after its own action to someone who holds no passkey', async () => {
		const { email } = await person(acme.bucketId);

		const { html } = await codeRequiredPage(email);

		expect(propsIn(html)).toMatchObject({ passkey: 'secondary' });
		expect(textOf(html)).toContain('Sign in with a passkey');
	});

	it('lets the person through to the app with the passkey that page offers', async () => {
		const { email, device } = await holdingPasskey(acme);
		const { browser, auth, html } = await codeRequiredPage(email);
		const link = present(
			/href="([^"]*\/login\?notice=passkey)"/.exec(html)?.[1],
			'the passkey link'
		);
		const login = await browser.open(link);
		const page = { url: login.url, html: await login.response.text() };
		expect(textOf(page.html)).toContain(
			'Sign in with your passkey to continue.'
		);

		const posted = await postPasskey(browser, device, acme, page);

		const code = await codeAfter(browser, posted, page.url);
		expect(claimsOf((await redeem(billing, auth, code)).id_token).acr).toBe(
			MULTI_FACTOR
		);
	});
});
