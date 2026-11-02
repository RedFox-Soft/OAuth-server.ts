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
import { adapter } from 'lib/adapters/index.ts';
import { eventBus } from 'lib/event_bus.js';
import epochTime from 'lib/helpers/epoch_time.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { dpopKey, dpopProof } from '../assertion_grants/helpers.ts';
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
	refused,
	signIn
} from './harness.ts';

const EVENTS = [
	'connected_account.exchanged',
	'connected_account.refreshed',
	'connected_account.broken'
] as const;

/**
 * @proves An exchange says nothing about another person's accounts, and no upstream token leaves except in the
 * exchange's own answer: not in a refusal, an event or an error record; a sender-constrained subject token is
 * honoured only with a proof of its key.
 */
describe('what an exchange gives away', () => {
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

	it('answers an invalid subject token the same whether or not anyone has an account there', async () => {
		const service = await githubService();
		await connected(unique('person'), service);
		const empty = await githubService();

		const withAccounts = refused(
			await exchange({ subjectToken: unique('forged'), audience: service.id })
		);
		const without = refused(
			await exchange({ subjectToken: unique('forged'), audience: empty.id })
		);

		expect(withAccounts).toEqual(without);
	});

	it('carries no upstream token in any event of an exchange that refreshes', async () => {
		const person = unique('person');
		const service = await githubService();
		const record = await connected(person, service, {
			accessTokenExpiresAt: epochTime() - 10
		});
		const signedIn = await signIn(setup, 'agent', person);
		await allowAccount(signedIn.grantId, record);
		const tokens = githubTokens();
		githubStub().expectToken(tokens);
		const seen: unknown[] = [];
		for (const name of EVENTS) {
			eventBus.on(name, (event: unknown) => seen.push(event));
		}

		try {
			granted(
				await exchange({
					subjectToken: signedIn.accessToken,
					audience: service.id
				})
			);
		} finally {
			for (const name of EVENTS) eventBus.removeAllListeners(name);
		}

		const text = JSON.stringify(seen);
		expect(seen.length).toBeGreaterThanOrEqual(2);
		for (const secret of [
			present(record.accessToken, 'old token'),
			present(record.refreshToken, 'old refresh token'),
			tokens.access_token,
			tokens.refresh_token
		]) {
			expect(text).not.toContain(secret);
		}
	});

	it('carries no upstream token in a refusal', async () => {
		const person = unique('person');
		const service = await githubService();
		const record = await connected(person, service);
		const signedIn = await signIn(setup, 'agent', person);
		await allowAccount(signedIn.grantId, record);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id,
				scope: 'admin:org'
			})
		);

		expect(JSON.stringify(body)).not.toContain(
			present(record.accessToken, 'a token')
		);
	});

	describe('a sender-constrained subject token presented by its own application', () => {
		async function bound() {
			const person = unique('person');
			const service = await githubService();
			const record = await connected(person, service);
			const signedIn = await signIn(setup, 'agent', person);
			await allowAccount(signedIn.grantId, record);
			const key = await dpopKey();
			const stored = present(
				await adapter('AccessToken').find(signedIn.accessToken),
				'the stored token'
			);
			await adapter('AccessToken').upsert(
				signedIn.accessToken,
				{ ...stored, jkt: key.thumbprint },
				3600
			);
			return { service, record, signedIn, key };
		}

		it('is refused without a proof of its key', async () => {
			const { service, signedIn } = await bound();

			const body = refused(
				await exchange({
					subjectToken: signedIn.accessToken,
					audience: service.id
				})
			);

			expect(body.error).toBe('invalid_grant');
		});

		it('is honoured with a proof of its key', async () => {
			const { service, record, signedIn, key } = await bound();

			const body = granted(
				await exchange({
					subjectToken: signedIn.accessToken,
					audience: service.id,
					dpop: await dpopProof(key.keypair)
				})
			);

			expect(body.access_token).toBe(present(record.accessToken, 'a token'));
		});
	});
});
