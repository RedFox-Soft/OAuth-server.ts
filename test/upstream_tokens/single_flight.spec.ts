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
import {
	getConnectedAccountStore,
	rawConnectedAccountStoreForTests
} from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import epochTime from 'lib/helpers/epoch_time.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { addService } from '../connected_services/harness.ts';
import {
	githubStub,
	githubTokens,
	slackStub,
	unique
} from '../connected_services/stubs.ts';
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
 * @proves However many requests need a refresh at once, in one process or several sharing the datastore, exactly
 * one reaches the provider and all receive its token; a provider that is down leaves the account usable, and one
 * that rejects the refresh, returns another account, or whose answer cannot be stored breaks it.
 */
describe('refreshing a person’s upstream token', () => {
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

	async function expired(fields: Parameters<typeof connected>[2] = {}) {
		const person = unique('person');
		const service = await githubService();
		const record = await connected(person, service, {
			accessTokenExpiresAt: epochTime() - 10,
			...fields
		});
		const signedIn = await signIn(setup, 'agent', person);
		await allowAccount(signedIn.grantId, record);
		return { service, record, signedIn };
	}

	const raw = (id: string) =>
		rawConnectedAccountStoreForTests().find(DEFAULT_BUCKET_ID, id);

	it('makes one refresh for fifty simultaneous exchanges, and gives all of them its token', async () => {
		const { service, signedIn } = await expired();
		const tokens = githubTokens();
		githubStub().expectToken(tokens);

		const answers = await Promise.all(
			Array.from({ length: 50 }, () =>
				exchange({ subjectToken: signedIn.accessToken, audience: service.id })
			)
		);

		expect(
			new Set(answers.map((answer) => granted(answer).access_token))
		).toEqual(new Set([tokens.access_token]));
	});

	it('waits for a refresh another process is making and uses its result', async () => {
		const { service, record, signedIn } = await expired();
		const store = getConnectedAccountStore();
		const now = epochTime();
		present(
			await store.claimRefresh(
				DEFAULT_BUCKET_ID,
				record._id,
				'elsewhere',
				now,
				now + 20
			),
			'the lease'
		);

		const pending = exchange({
			subjectToken: signedIn.accessToken,
			audience: service.id
		});
		await Bun.sleep(300);
		await store.finishRefresh(DEFAULT_BUCKET_ID, record._id, 'elsewhere', {
			accessToken: 'refreshed-elsewhere',
			tokenType: 'bearer',
			accessTokenExpiresAt: epochTime() + 3600,
			scopes: record.scopes,
			refreshedAt: epochTime()
		});

		expect(granted(await pending).access_token).toBe('refreshed-elsewhere');
	});

	it('takes over a refresh whose holder stopped', async () => {
		const { service, record, signedIn } = await expired();
		const now = epochTime();
		await getConnectedAccountStore().claimRefresh(
			DEFAULT_BUCKET_ID,
			record._id,
			'stopped',
			now,
			now + 1
		);
		const tokens = githubTokens();
		githubStub().expectToken(tokens);

		const body = granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.access_token).toBe(tokens.access_token);
	});

	it('answers temporarily unavailable while the provider is down, and keeps the account usable', async () => {
		const { service, record, signedIn } = await expired();
		githubStub().expectRefreshUnavailable();

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			}),
			503
		);

		expect(body.reason).toBe('temporarily_unavailable');
		const stored = present(await raw(record._id), 'the account');
		expect(stored.broken).toBeUndefined();
		expect(stored.refreshLease).toBeUndefined();
		const tokens = githubTokens();
		githubStub().expectToken(tokens);
		expect(
			granted(
				await exchange({
					subjectToken: signedIn.accessToken,
					audience: service.id
				})
			).access_token
		).toBe(tokens.access_token);
	});

	it('breaks the account when the provider rejects the refresh', async () => {
		const { service, record, signedIn } = await expired();
		githubStub().expectRefreshRejected();

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.reason).toBe('reconnect_required');
		expect(present(await raw(record._id), 'the account').broken?.reason).toBe(
			'refresh_rejected'
		);
	});

	it('breaks the account when the refreshed tokens could not be stored', async () => {
		const { service, record, signedIn } = await expired();
		/* Another process takes the lease while the provider is answering, so this one's write is refused. */
		githubStub().expectToken(githubTokens(), () => {
			void getConnectedAccountStore().claimRefresh(
				DEFAULT_BUCKET_ID,
				record._id,
				'thief',
				epochTime() + 1000,
				epochTime() + 2000
			);
			return true;
		});

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.reason).toBe('reconnect_required');
		expect(present(await raw(record._id), 'the account').broken?.reason).toBe(
			'refresh_unsaved'
		);
	});

	it('breaks the account and discards the tokens when the refresh names another account', async () => {
		const person = unique('person');
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'slack',
			scopes: ['users:read'],
			displayName: 'Slack',
			applications: ['agent']
		});
		const record = await connected(person, service, {
			upstreamId: 'T0001:U0001',
			scopes: ['users:read'],
			accessTokenExpiresAt: epochTime() - 10
		});
		const signedIn = await signIn(setup, 'agent', person);
		await allowAccount(signedIn.grantId, record);
		slackStub().expectToken({
			ok: true,
			team: { id: 'T0001' },
			authed_user: {
				id: 'U9999',
				access_token: unique('xoxp-other'),
				refresh_token: unique('xoxe-other'),
				expires_in: 43200,
				token_type: 'user'
			}
		});

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.reason).toBe('reconnect_required');
		const stored = present(await raw(record._id), 'the account');
		expect(stored.broken?.reason).toBe('identity_changed');
	});

	it('keeps the refresh token the provider did not replace', async () => {
		const { service, record, signedIn } = await expired();
		const before = present(await raw(record._id), 'the account').refreshToken;
		githubStub().expectToken({
			access_token: unique('gho_access'),
			token_type: 'bearer',
			scope: 'repo,read:user',
			expires_in: 28800
		});

		granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(present(await raw(record._id), 'the account').refreshToken).toBe(
			before
		);
	});

	it('refuses an exchange needing a scope the refresh no longer granted', async () => {
		const { service, signedIn } = await expired();
		githubStub().expectToken(githubTokens({ scope: 'read:user' }));

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id,
				scope: 'repo'
			})
		);

		expect(body.reason).toBe('reconnect_required');
	});

	it('never hands out a token of an account disconnected while the exchange waited', async () => {
		const { service, record, signedIn } = await expired();
		const now = epochTime();
		await getConnectedAccountStore().claimRefresh(
			DEFAULT_BUCKET_ID,
			record._id,
			'elsewhere',
			now,
			now + 20
		);

		const pending = exchange({
			subjectToken: signedIn.accessToken,
			audience: service.id
		});
		await Bun.sleep(300);
		await getConnectedAccountStore().destroy(DEFAULT_BUCKET_ID, record._id);

		expect(refused(await pending).reason).toBe('connect_required');
	});
});
