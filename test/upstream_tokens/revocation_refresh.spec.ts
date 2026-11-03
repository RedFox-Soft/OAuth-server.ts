import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { disconnect } from 'lib/connected_services/accounts.ts';
import epochTime from 'lib/helpers/epoch_time.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { addService } from '../connected_services/harness.ts';
import {
	githubStub,
	githubTokens,
	slackStub,
	unique
} from '../connected_services/stubs.ts';
import { connected, githubService, project } from './harness.ts';

/**
 * @proves Disconnecting an account whose access token expired, at a provider that revokes with the access token,
 * refreshes first and revokes with the new token, within the five seconds a disconnect is bound to; a failed refresh
 * still deletes the account and says the provider was not told.
 */
describe('disconnecting an account whose access token expired', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'upstream_tokens' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	it('refreshes a GitHub token and revokes the grant with the new one', async () => {
		const service = await githubService();
		const record = await connected(unique('person'), service, {
			accessTokenExpiresAt: epochTime() - 10
		});
		const github = githubStub();
		const tokens = githubTokens();
		github.expectToken(tokens, (form) =>
			form.includes('grant_type=refresh_token')
		);
		github.expectRevoke(service.clientId, 204, (body) =>
			body.includes(tokens.access_token)
		);
		const started = Date.now();

		const result = await disconnect({
			bucket: await project(),
			accountId: record.accountId,
			connectedAccountId: record._id,
			by: 'person'
		});

		expect(result).toMatchObject({ removed: true, revocation: 'revoked' });
		expect(Date.now() - started).toBeLessThan(5_000);
	});

	it('refreshes a Slack token and revokes with the new one', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'slack',
			scopes: ['users:read'],
			displayName: 'Slack'
		});
		const record = await connected(unique('person'), service, {
			upstreamId: 'T0001:U0001',
			accessTokenExpiresAt: epochTime() - 10
		});
		const slack = slackStub();
		slack.expectToken({
			ok: true,
			team: { id: 'T0001' },
			authed_user: {
				id: 'U0001',
				access_token: unique('xoxp-fresh'),
				refresh_token: unique('xoxe-fresh'),
				expires_in: 43200,
				token_type: 'user'
			}
		});
		slack.expectRevoke(true);

		const result = await disconnect({
			bucket: await project(),
			accountId: record.accountId,
			connectedAccountId: record._id,
			by: 'person'
		});

		expect(result).toMatchObject({ removed: true, revocation: 'revoked' });
	});

	it('deletes the account when the refresh fails, and says the provider was not told', async () => {
		const service = await githubService();
		const record = await connected(unique('person'), service, {
			accessTokenExpiresAt: epochTime() - 10
		});
		const github = githubStub();
		github.expectRefreshRejected();
		github.expectRevoke(service.clientId, 404);

		const result = await disconnect({
			bucket: await project(),
			accountId: record.accountId,
			connectedAccountId: record._id,
			by: 'person'
		});

		expect(result).toMatchObject({ removed: true, revocation: 'failed' });
	});
});
