import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock
} from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { adminAuditStore, getBucketStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { endApplicationAccess } from 'lib/end_users/service.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { textOf } from '../connected_apps/helpers.ts';
import { PAGE, callback } from '../connected_services/harness.ts';
import {
	githubStub,
	githubTokens,
	unique
} from '../connected_services/stubs.ts';
import {
	allowAccount,
	connected,
	exchange,
	githubService,
	granted,
	project,
	refused
} from '../upstream_tokens/harness.ts';
import { act, linkFor, locationOf, personAndAgent, read } from './harness.ts';

/**
 * @proves A person whose agent was refused for want of their consent gives it from the agent's link, for the account
 * the agent named or the ones they tick, and it is the account page's own consent; declining, an agent whose access
 * ended, or an application the administrator no longer allows changes nothing.
 */
describe('allowing an agent from its link', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'connect_link' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	async function withAccounts(count: number) {
		const service = await githubService();
		const owner = await personAndAgent(setup);
		const records = [];
		for (let i = 0; i < count; i += 1) {
			records.push(await connected(owner.accountId, service));
		}
		const { path } = await linkFor(owner.signedIn, service);
		return { service, owner, records, path };
	}

	function exchangeAs(
		owner: Awaited<ReturnType<typeof personAndAgent>>,
		serviceId: string,
		loginHint?: string
	) {
		return exchange({
			subjectToken: owner.signedIn.accessToken,
			audience: serviceId,
			...(loginHint ? { loginHint } : {})
		});
	}

	it('offers the one account and lets the next exchange succeed once allowed', async () => {
		const { service, owner, records, path } = await withAccounts(1);
		const page = await read(owner.browser, path);
		expect(page.text).toContain(records[0].label);

		const pressed = await act(owner.browser, path, {
			action: 'allow',
			connectedAccountId: records[0]._id
		});
		const done = await read(owner.browser, locationOf(pressed).toString());

		expect(done.text).toContain('can now use your GitHub account');
		granted(await exchangeAs(owner, service.id));
	});

	it('offers each of several accounts unticked and allows only the ticked one', async () => {
		const { service, owner, records, path } = await withAccounts(2);
		const page = await read(owner.browser, path);
		expect(page.html).not.toContain('checked');

		await act(owner.browser, path, {
			action: 'allow',
			connectedAccountId: records[0]._id
		});

		granted(await exchangeAs(owner, service.id, records[0].label));
		expect(
			refused(await exchangeAs(owner, service.id, records[1].label)).reason
		).toBe('consent_required');
	});

	it('records the account page’s own consent, listed, audited and withdrawn there', async () => {
		const { service, owner, records, path } = await withAccounts(1);
		await act(owner.browser, path, {
			action: 'allow',
			connectedAccountId: records[0]._id
		});

		const listed = textOf(await (await owner.browser.request(PAGE)).text());
		const { entries } = await adminAuditStore.list({
			targetId: owner.accountId
		});
		await act(owner.browser, PAGE, {
			action: 'withdraw',
			connectedAccountId: records[0]._id,
			clientId: 'agent'
		});

		expect(listed).toContain('Applications that may use it');
		expect(
			entries.find((entry) => entry.action === 'connected.account.consent')
		).toMatchObject({ clientId: 'agent', to: 'allowed' });
		expect(refused(await exchangeAs(owner, service.id)).reason).toBe(
			'consent_required'
		);
	});

	it('changes nothing and closes the link when the person declines', async () => {
		const { service, owner, path } = await withAccounts(1);

		await act(owner.browser, path, { action: 'decline' });
		const again = await read(owner.browser, path);

		expect(again.status).toBe(404);
		expect(refused(await exchangeAs(owner, service.id)).reason).toBe(
			'consent_required'
		);
	});

	it('allows nothing for an agent whose access the person ended', async () => {
		const { owner, path } = await withAccounts(1);
		await endApplicationAccess(
			await project(),
			owner.accountId,
			'agent',
			async () => {
				await Promise.resolve();
			}
		);

		const page = await read(owner.browser, path);

		expect(page.html).not.toContain('name="xsrf"');
	});

	it('offers nothing once the administrator no longer allows the application', async () => {
		const { service, owner, path } = await withAccounts(1);
		const bucket = present(
			await getBucketStore().find(DEFAULT_BUCKET_ID),
			'the project'
		);
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			connectedServices: (bucket.connectedServices ?? []).map((item) =>
				item.id === service.id ? { ...item, applications: [] } : item
			)
		});

		const page = await read(owner.browser, path);

		expect(page.text).toContain('may no longer use GitHub');
		expect(page.html).not.toContain('name="xsrf"');
	});

	it('says it is already done when the consent was given on the account page', async () => {
		const { owner, records, path } = await withAccounts(1);
		await allowAccount(owner.signedIn.grantId, records[0]);

		const page = await read(owner.browser, path);

		expect(page.text).toContain('already done');
		expect(page.html).not.toContain('name="xsrf"');
	});

	it('allows the agent an account connected from the link instead', async () => {
		const { service, owner, path } = await withAccounts(2);
		const login = unique('another');
		const github = githubStub();
		const pressed = await act(owner.browser, path, { action: 'connect' });
		github.expectToken(githubTokens());
		github.expectUser({ id: 9191, login });

		await callback(owner.browser, locationOf(pressed));

		granted(await exchangeAs(owner, service.id, login));
	});
});
