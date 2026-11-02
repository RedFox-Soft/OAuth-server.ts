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
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import {
	allowAccount,
	connected,
	exchange,
	githubService,
	granted
} from '../upstream_tokens/harness.ts';
import { personAndAgent, refusedWith } from './harness.ts';

/**
 * @proves An agent allowed several of a person's accounts at a service, and naming none, learns the labels of exactly
 * those accounts and no link, so it can ask the person in the conversation and name one; accounts it was not allowed
 * stay unnamed.
 */
describe('an agent choosing among the accounts it may use', () => {
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

	async function threeAccounts() {
		const service = await githubService();
		const owner = await personAndAgent(setup);
		const work = await connected(owner.accountId, service);
		const home = await connected(owner.accountId, service);
		const hidden = await connected(owner.accountId, service);
		await allowAccount(owner.signedIn.grantId, work);
		await allowAccount(owner.signedIn.grantId, home);
		return { service, owner, work, home, hidden };
	}

	it('lists exactly the labels it may use, and no link', async () => {
		const { service, owner, work, home, hidden } = await threeAccounts();

		const body = refusedWith(
			await exchange({
				subjectToken: owner.signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.reason).toBe('account_selection_required');
		expect(body.accounts).toEqual([work.label, home.label].sort());
		expect(JSON.stringify(body)).not.toContain(hidden.label);
		expect(body.connect_uri).toBeUndefined();
	});

	it('receives the token of the account it names from the list', async () => {
		const { service, owner, home } = await threeAccounts();

		const body = granted(
			await exchange({
				subjectToken: owner.signedIn.accessToken,
				audience: service.id,
				loginHint: home.label
			})
		);

		expect(body.access_token).toBeString();
	});
});
