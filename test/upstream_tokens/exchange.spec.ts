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
import epochTime from 'lib/helpers/epoch_time.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { SEALED_PREFIX } from 'lib/sealing/seal.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import {
	githubStub,
	githubTokens,
	unique
} from '../connected_services/stubs.ts';
import {
	ACCESS_TOKEN_TYPE,
	allowAccount,
	connected,
	exchange,
	githubService,
	granted,
	refused,
	signIn
} from './harness.ts';

/**
 * @proves An application the administrator allowed, holding the person's consent, receives the person's upstream
 * access token for a connected service, refreshed when it is about to expire, and never the upstream refresh token.
 */
describe('an agent exchanging the person’s access token for their GitHub token', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	async function ready(fields: Parameters<typeof connected>[2] = {}) {
		const person = unique('person');
		const service = await githubService();
		const record = await connected(person, service, fields);
		const signedIn = await signIn(setup, 'agent', person);
		await allowAccount(signedIn.grantId, record);
		return { service, record, signedIn };
	}

	it('receives the stored token, its lifetime and scopes, and never a refresh token', async () => {
		const { service, record, signedIn } = await ready();

		const body = granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.access_token).toBe(present(record.accessToken, 'a token'));
		expect(body.issued_token_type).toBe(ACCESS_TOKEN_TYPE);
		expect(body.token_type).toBe('Bearer');
		expect(body.scope).toBe('repo read:user');
		expect(present(body.expires_in, 'a lifetime')).toBeGreaterThan(3500);
		expect(body.refresh_token).toBeUndefined();
	});

	it('returns a token with more than a minute left without asking the provider', async () => {
		const { service, record, signedIn } = await ready({
			accessTokenExpiresAt: epochTime() + 120
		});

		const body = granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.access_token).toBe(present(record.accessToken, 'a token'));
	});

	it('refreshes an expired token, stores the new one sealed and returns it', async () => {
		const { service, record, signedIn } = await ready({
			accessTokenExpiresAt: epochTime() - 10
		});
		const tokens = githubTokens({ scope: 'repo,read:user' });
		githubStub().expectToken(
			tokens,
			(form) =>
				form.includes('grant_type=refresh_token') &&
				form.includes(
					`refresh_token=${encodeURIComponent(present(record.refreshToken, 'a refresh token'))}`
				)
		);

		const body = granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.access_token).toBe(tokens.access_token);
		const stored = present(
			await rawConnectedAccountStoreForTests().find(
				DEFAULT_BUCKET_ID,
				record._id
			),
			'the stored account'
		);
		expect(stored.accessToken?.startsWith(SEALED_PREFIX)).toBe(true);
		expect(stored.refreshToken?.startsWith(SEALED_PREFIX)).toBe(true);
		expect(stored.refreshLease).toBeUndefined();
	});

	it('returns a token that does not expire as stored, with no lifetime', async () => {
		const { service, record, signedIn } = await ready({
			accessTokenExpiresAt: undefined,
			refreshToken: undefined
		});

		const body = granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.access_token).toBe(present(record.accessToken, 'a token'));
		expect(body.expires_in).toBeUndefined();
	});

	it('refuses a scope the account was not granted, naming it, as needing reconnection', async () => {
		const { service, signedIn } = await ready();

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id,
				scope: 'repo admin:org'
			})
		);

		expect(body.error).toBe('invalid_grant');
		expect(body.reason).toBe('reconnect_required');
		expect(body.error_description).toContain('admin:org');
		expect(body.error_description).not.toContain('repo ');
	});
});
