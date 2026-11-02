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
import epochTime from 'lib/helpers/epoch_time.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { OTHER_KEYRING, TEST_KEYRING } from '../sealing/fixtures.ts';
import { unique } from '../connected_services/stubs.ts';
import {
	allowAccount,
	allowService,
	connected,
	exchange,
	githubService,
	refused,
	signIn
} from './harness.ts';

/**
 * @proves The refusal tells the developer what the person must do: connect the service first, or reconnect an
 * account the provider no longer honours or whose tokens can no longer be read.
 */
describe('an exchange for an account that cannot be used', () => {
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

	it('tells the agent the person must connect the service first', async () => {
		const person = unique('person');
		const service = await githubService();
		const signedIn = await signIn(setup, 'agent', person);
		await allowService(signedIn.grantId, service);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.error).toBe('invalid_grant');
		expect(body.reason).toBe('connect_required');
	});

	it('tells the agent the person must reconnect an account the provider rejected', async () => {
		const person = unique('person');
		const service = await githubService();
		const record = await connected(person, service, {
			broken: { reason: 'refresh_rejected', at: epochTime(), notified: true }
		});
		const signedIn = await signIn(setup, 'agent', person);
		await allowAccount(signedIn.grantId, record);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.reason).toBe('reconnect_required');
	});

	it('tells the agent the person must reconnect an account whose tokens cannot be read', async () => {
		const person = unique('person');
		const service = await githubService();
		/* Sealed under a key this deployment no longer has, as after a lost keyring (specs/116). */
		resetKeyringForTests(OTHER_KEYRING);
		const record = await connected(person, service);
		resetKeyringForTests(TEST_KEYRING);
		const signedIn = await signIn(setup, 'agent', person);
		await allowAccount(signedIn.grantId, record);

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.reason).toBe('reconnect_required');
	});
});
