import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock,
	spyOn
} from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { unique } from '../connected_services/stubs.ts';
import {
	allowAccount,
	connected,
	exchange,
	githubService,
	granted,
	refused,
	signIn
} from './harness.ts';

/**
 * @proves With several accounts at one service, an agent gets only an account the person allowed it: the one, or
 * the one it names by label, and never a guess when it names none.
 */
describe('an agent exchanging for a person with two GitHub accounts', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'upstream_tokens' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	async function twoAccounts() {
		const person = unique('person');
		const service = await githubService();
		const work = await connected(person, service, { label: unique('work') });
		const home = await connected(person, service, { label: unique('home') });
		const signedIn = await signIn(setup, 'agent', person);
		return { service, work, home, signedIn };
	}

	it('receives the one account the person allowed when it names none', async () => {
		const { service, work, signedIn } = await twoAccounts();
		await allowAccount(signedIn.grantId, work);

		const body = granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.access_token).toBe(present(work.accessToken, 'a token'));
	});

	it('receives the account it names by label when the person allowed both', async () => {
		const { service, work, home, signedIn } = await twoAccounts();
		await allowAccount(signedIn.grantId, work);
		await allowAccount(signedIn.grantId, home);

		const body = granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id,
				loginHint: home.label
			})
		);

		expect(body.access_token).toBe(present(home.accessToken, 'a token'));
	});

	it('is asked to choose when the person allowed both and it names none, and learns no label', async () => {
		const { service, work, home, signedIn } = await twoAccounts();
		await allowAccount(signedIn.grantId, work);
		await allowAccount(signedIn.grantId, home);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.reason).toBe('account_selection_required');
		expect(body.error_description).not.toContain(work.label);
		expect(body.error_description).not.toContain(home.label);
	});

	it('is refused as needing consent when it names an account the person did not allow', async () => {
		const { service, work, home, signedIn } = await twoAccounts();
		await allowAccount(signedIn.grantId, work);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id,
				loginHint: home.label
			})
		);

		expect(body.reason).toBe('consent_required');
	});
});
