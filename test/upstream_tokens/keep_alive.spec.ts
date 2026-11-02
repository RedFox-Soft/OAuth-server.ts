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
import { rawConnectedAccountStoreForTests } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { eventBus } from 'lib/event_bus.js';
import { keepAlivePass } from 'lib/connected_services/keep_alive.ts';
import epochTime from 'lib/helpers/epoch_time.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import {
	githubStub,
	githubTokens,
	unique
} from '../connected_services/stubs.ts';
import { allowAccount, connected, githubService, signIn } from './harness.ts';

const DAY = 86_400;

/**
 * @proves An account an agent may use and used within a year is refreshed before its provider discards an idle
 * refresh token, at most once however many processes run the pass; an account no agent may use, or none used for a
 * year, is left to lapse.
 */
describe('keeping connected accounts alive', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'upstream_tokens' });
	});

	beforeEach(async () => {
		resetKeyringForTests(TEST_KEYRING);
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
		/* Each case owns every account the pass sees. */
		await rawConnectedAccountStoreForTests().destroyByBucket(DEFAULT_BUCKET_ID);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	async function account(
		fields: Parameters<typeof connected>[2],
		allowed = true
	) {
		const person = unique('person');
		const service = await githubService();
		const record = await connected(person, service, fields);
		const signedIn = await signIn(setup, 'agent', person);
		if (allowed) await allowAccount(signedIn.grantId, record);
		return record;
	}

	const raw = async (id: string) =>
		present(
			await rawConnectedAccountStoreForTests().find(DEFAULT_BUCKET_ID, id),
			'the account'
		);

	const now = epochTime();
	const used = (at: number) => [{ clientId: 'agent', at }];

	it('refreshes an account in use that was not refreshed for a month', async () => {
		const record = await account({
			refreshedAt: now - 40 * DAY,
			usedBy: used(now - 60 * DAY)
		});
		githubStub().expectToken(githubTokens());

		expect(await keepAlivePass(now)).toBe(1);
		expect((await raw(record._id)).refreshedAt).toBeGreaterThan(now - 40 * DAY);
	});

	it('leaves an account no agent may use to lapse', async () => {
		await account(
			{ refreshedAt: now - 40 * DAY, usedBy: used(now - DAY) },
			false
		);

		expect(await keepAlivePass(now)).toBe(0);
	});

	it('leaves an account no agent used for a year to lapse', async () => {
		await account({
			refreshedAt: now - 40 * DAY,
			usedBy: used(now - 400 * DAY)
		});

		expect(await keepAlivePass(now)).toBe(0);
	});

	it('refreshes one whose refresh token expires within a week though refreshed lately', async () => {
		await account({
			refreshedAt: now - DAY,
			refreshTokenExpiresAt: now + 3 * DAY,
			usedBy: used(now - DAY)
		});
		githubStub().expectToken(githubTokens());

		expect(await keepAlivePass(now)).toBe(1);
	});

	it('breaks an account the provider rejects', async () => {
		const record = await account({
			refreshedAt: now - 40 * DAY,
			usedBy: used(now - DAY)
		});
		githubStub().expectRefreshRejected();

		await keepAlivePass(now);

		expect((await raw(record._id)).broken?.reason).toBe('refresh_rejected');
	});

	it('refreshes an account once when two passes run at the same time', async () => {
		await account({ refreshedAt: now - 40 * DAY, usedBy: used(now - DAY) });
		githubStub().expectToken(githubTokens());

		let refreshes = 0;
		const count = () => {
			refreshes += 1;
		};
		eventBus.on('connected_account.refreshed', count);

		try {
			await Promise.all([keepAlivePass(now), keepAlivePass(now)]);
		} finally {
			eventBus.off('connected_account.refreshed', count);
		}

		expect(refreshes).toBe(1);
	});
});
