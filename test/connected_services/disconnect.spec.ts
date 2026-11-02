import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { ISSUER } from 'lib/configs/env.js';
import { textOf, xsrfFrom } from '../connected_apps/helpers.ts';
import { present } from '../shape.ts';
import {
	accountsOf,
	addService,
	PAGE,
	postDisconnect,
	seededAccount,
	signedInPerson
} from './harness.ts';
import { githubStub } from './stubs.ts';

async function landedOn(
	browser: Awaited<ReturnType<typeof signedInPerson>>['browser'],
	response: Response
) {
	expect(response.status).toBe(303);
	const page = await browser.request(
		new URL(
			present(response.headers.get('location'), 'the page'),
			ISSUER
		).toString()
	);
	const html = await page.text();
	return { html, text: textOf(html) };
}

/**
 * @proves A person takes back access they gave: disconnecting deletes the account here whatever the provider
 * answers, asks the provider to revoke it, and tells the person where to finish the job when it could not.
 */
describe('a person disconnecting an account', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});
	afterEach(() => {
		assertNoPendingInterceptors();
	});

	it('revokes the grant at the provider and deletes the account', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github',
			displayName: 'GitHub'
		});
		const who = await signedInPerson();
		const account = await seededAccount(who, service);
		githubStub().expectRevoke(service.clientId, 204, (body) =>
			body.includes(String(account.accessToken))
		);

		const { text } = await landedOn(
			who.browser,
			await postDisconnect(who.browser, account._id)
		);

		expect(text).toContain('GitHub was asked to cancel the access and agreed.');
		expect(await accountsOf(who.accountId)).toEqual([]);
	});

	it('deletes the account when the provider refuses, and says the provider was not told', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github',
			displayName: 'GitHub'
		});
		const who = await signedInPerson();
		const account = await seededAccount(who, service);
		githubStub().expectRevoke(service.clientId, 500);

		const { text, html } = await landedOn(
			who.browser,
			await postDisconnect(who.browser, account._id)
		);

		expect(text).toContain('GitHub could not be reached to cancel the access.');
		expect(html).toContain('https://github.com/settings/applications');
		expect(await accountsOf(who.accountId)).toEqual([]);
	});

	it('deletes the account at a provider with no revocation, and links to its access page', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'microsoft',
			tenant: 'common',
			displayName: 'Microsoft'
		});
		const who = await signedInPerson();
		const account = await seededAccount(who, service);

		const { text, html } = await landedOn(
			who.browser,
			await postDisconnect(who.browser, account._id)
		);

		expect(text).toContain(
			'Microsoft does not let this server cancel the access.'
		);
		expect(html).toContain('https://myapps.microsoft.com');
		expect(await accountsOf(who.accountId)).toEqual([]);
	});

	it('refuses to disconnect another person’s account, as if it did not exist', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github'
		});
		const owner = await signedInPerson();
		const account = await seededAccount(owner, service);
		const other = await signedInPerson();
		// The other person's own page gives them a valid form value; the account id is the owner's.
		const page = await other.browser.request(
			`${PAGE}?connect=${encodeURIComponent(service.id)}`
		);
		const xsrf = xsrfFrom(await page.text());

		const response = await other.browser.post(PAGE, {
			action: 'disconnect',
			connectedAccountId: account._id,
			xsrf
		});

		expect(response.status).toBe(303);
		expect(response.headers.get('location')).not.toContain('done=');
		expect(await accountsOf(owner.accountId)).toHaveLength(1);
	});
});
