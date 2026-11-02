import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock,
	setSystemTime,
	spyOn
} from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { adminAuditStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { endApplicationAccess } from 'lib/end_users/service.ts';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { textOf, xsrfFrom } from '../connected_apps/helpers.ts';
import { unique } from '../connected_services/stubs.ts';
import { PAGE, admin, signedInPerson } from '../connected_services/harness.ts';
import {
	allowAccount,
	connected,
	exchange,
	githubService,
	granted,
	project,
	refused,
	signIn
} from './harness.ts';

/**
 * @proves The person sees on their account page which applications may use each connected account and when each
 * last did, gives and withdraws that use with their own recent action on the page, and an administrator sees the
 * same without any token; removing an application's access removes its use with it.
 */
describe('a person managing which applications use their connected accounts', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'upstream_tokens' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(() => {
		setSystemTime();
		assertNoPendingInterceptors();
		mock.restore();
	});

	/* A person signed in to their account page and to the agent, with one GitHub account the agent may use. */
	async function personWithAgent(allowed = true) {
		const service = await githubService();
		const pagePerson = await signedInPerson();
		const record = await connected(pagePerson.accountId, service);
		const signedIn = await signIn(setup, 'agent', pagePerson.accountId);
		if (allowed) await allowAccount(signedIn.grantId, record);
		return { service, record, signedIn, ...pagePerson };
	}

	it('lists the applications that may use each account, with their last use', async () => {
		const { service, browser, signedIn } = await personWithAgent();
		granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		const text = textOf(await (await browser.request(PAGE)).text());

		expect(text).toContain('Applications that may use it');
		expect(text).toContain('agent');
		expect(text).toContain('last used');
		expect(text).not.toContain('<time');
	});

	it('refuses the next exchange once the person withdraws, and says tokens already given expire on their own', async () => {
		const { service, record, browser, signedIn, accountId } =
			await personWithAgent();
		const xsrf = xsrfFrom(await (await browser.request(PAGE)).text());

		const response = await browser.post(PAGE, {
			action: 'withdraw',
			connectedAccountId: record._id,
			clientId: 'agent',
			xsrf
		});
		const landedOn = textOf(
			await (
				await browser.request(response.headers.get('location') ?? PAGE)
			).text()
		);

		expect(landedOn).toContain('usually within an hour');
		expect(
			refused(
				await exchange({
					subjectToken: signedIn.accessToken,
					audience: service.id
				})
			).reason
		).toBe('consent_required');
		const { entries } = await adminAuditStore.list({ targetId: accountId });
		expect(
			entries.find((entry) => entry.action === 'connected.account.consent')
		).toMatchObject({ clientId: 'agent', to: 'withdrawn' });
	});

	it('lets the agent use an account the person allows on the page', async () => {
		const { service, record, browser, signedIn } = await personWithAgent(false);
		const html = await (await browser.request(PAGE)).text();
		expect(textOf(html)).toContain('Let an application use it');

		await browser.post(PAGE, {
			action: 'allow',
			connectedAccountId: record._id,
			clientId: 'agent',
			xsrf: xsrfFrom(html)
		});

		granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);
	});

	it('changes nothing for a request without the page’s token, from another site, or after a stale sign-in', async () => {
		const { service, record, browser, signedIn } = await personWithAgent();
		const xsrf = xsrfFrom(await (await browser.request(PAGE)).text());
		const withdraw = {
			action: 'withdraw',
			connectedAccountId: record._id,
			clientId: 'agent'
		};

		await browser.post(PAGE, { ...withdraw, xsrf: 'forged' });
		await browser.post(
			PAGE,
			{ ...withdraw, xsrf },
			{
				origin: 'https://evil.example'
			}
		);
		setSystemTime(new Date(Date.now() + 16 * 60 * 1000));
		const stale = await browser.post(PAGE, { ...withdraw, xsrf });
		setSystemTime();

		expect(stale.headers.get('location') ?? '').toContain('prompt=login');
		granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);
	});

	it('answers withdrawing a use that is already gone as done', async () => {
		const { record, browser } = await personWithAgent(false);
		const xsrf = xsrfFrom(await (await browser.request(PAGE)).text());

		const response = await browser.post(PAGE, {
			action: 'withdraw',
			connectedAccountId: record._id,
			clientId: 'agent',
			xsrf
		});

		expect(response.status).toBe(303);
		expect(response.headers.get('location') ?? '').toContain('done=withdrawn');
	});

	it('refuses allowing an application the person never gave access to', async () => {
		const { record, browser } = await personWithAgent(false);
		const xsrf = xsrfFrom(await (await browser.request(PAGE)).text());

		const response = await browser.post(PAGE, {
			action: 'allow',
			connectedAccountId: record._id,
			clientId: 'other-agent',
			xsrf
		});

		expect(response.headers.get('location') ?? '').not.toContain('done=');
	});

	it('removes the use with the application’s access', async () => {
		const { service, signedIn, accountId } = await personWithAgent();

		await endApplicationAccess(
			await project(),
			accountId,
			'agent',
			async () => {
				await Promise.resolve();
			}
		);

		expect(
			(
				await exchange({
					subjectToken: signedIn.accessToken,
					audience: service.id
				})
			).status
		).not.toBe(200);
	});

	it('shows an administrator which applications may use each account, and no token', async () => {
		const { service, record, signedIn, accountId } = await personWithAgent();
		granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);
		const cookie = await cookieFor(await createAdministrator('super'));

		const answer = await admin(
			cookie,
			'GET',
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/users/${accountId}/connected-accounts`
		);

		expect(JSON.stringify(answer.json)).toContain('"clientId":"agent"');
		expect(JSON.stringify(answer.json)).toContain('lastUsedAt');
		expect(JSON.stringify(answer.json)).not.toContain(
			record.accessToken ?? unique('never')
		);
	});
});
