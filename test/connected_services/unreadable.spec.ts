import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { getBucketStore } from 'lib/adapters/index.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { keyringStatus } from 'lib/sealing/status.ts';
import { OTHER_KEYRING, TEST_KEYRING } from '../sealing/fixtures.ts';
import {
	accountsOf,
	addService,
	callback,
	landed,
	PAGE,
	seededAccount,
	signedInPerson,
	startConnect
} from './harness.ts';
import { textOf } from '../connected_apps/helpers.ts';
import { githubStub, githubTokens } from './stubs.ts';

/**
 * @proves After the keyring that sealed a connected account is lost, the account is shown as needing to be
 * connected again rather than hidden, is counted where every unreadable secret is, and connecting again repairs
 * it.
 */
describe('a connected account sealed under a keyring no longer in use', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});
	afterEach(() => {
		resetKeyringForTests(TEST_KEYRING);
		assertNoPendingInterceptors();
	});

	it('is listed as needing to be connected again', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github',
			displayName: 'GitHub'
		});
		const who = await signedInPerson();
		await seededAccount(who, service, { label: 'lost-key-account' });
		resetKeyringForTests(OTHER_KEYRING);

		const page = await who.browser.request(PAGE);

		const text = textOf(await page.text());
		expect(text).toContain('lost-key-account');
		expect(text).toContain('Needs to be connected again');
	});

	it('is replaced by readable tokens when the person connects the same account again', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github',
			scopes: ['read:user']
		});
		const who = await signedInPerson();
		await seededAccount(who, service, { upstreamId: '4242' });
		resetKeyringForTests(OTHER_KEYRING);
		// The service's own secret was sealed under the lost keyring too: an administrator re-enters it first.
		await getBucketStore().update(who.bucket._id, {
			connectedServices: [{ ...service, clientSecret: 're-entered-secret' }]
		});
		const stub = githubStub();
		const authorize = await startConnect(who.browser, service.id);
		stub.expectToken(githubTokens());
		stub.expectUser({ id: 4242, login: 'repaired' });

		const text = await landed(
			who.browser,
			await callback(who.browser, authorize)
		);

		expect(text).not.toContain('Needs to be connected again');
		expect(await accountsOf(who.accountId)).toHaveLength(1);
	});

	it('is counted in the keyring status with the person it belongs to', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github'
		});
		const who = await signedInPerson();
		const account = await seededAccount(who, service);
		resetKeyringForTests(OTHER_KEYRING);
		await who.browser.request(PAGE);

		const status = await keyringStatus();

		const entry = status.unreadable.find(
			(item) =>
				item.kind === 'connectedAccountToken' && item.owner.id === account._id
		);
		expect(entry?.owner).toMatchObject({
			bucketId: who.bucket._id,
			accountId: who.accountId
		});
	});
});
