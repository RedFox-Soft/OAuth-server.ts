import { afterEach, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { ISSUER } from 'lib/configs/env.js';
import { getConnectedAccountStore } from 'lib/adapters/index.ts';
import { connectedAccountId } from 'lib/connected_services/accounts.ts';
import { eventBus } from 'lib/event_bus.ts';
import { KeyringRequired } from 'lib/sealing/decorators.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { textOf, xsrfFrom } from '../connected_apps/helpers.ts';
import { present } from '../shape.ts';
import {
	accountsOf,
	addService,
	callback,
	landed,
	PAGE,
	signedInPerson,
	startConnect
} from './harness.ts';
import { githubStub, githubTokens, unique } from './stubs.ts';

async function github(scopes: string[] = ['read:user']) {
	return addService({
		kind: 'catalogue',
		catalogueId: 'github',
		scopes,
		displayName: 'GitHub'
	});
}

/**
 * @proves Whatever the provider answers, a person is told what happened in their language, nothing is stored that
 * should not be, and no token is ever kept without a keyring or carried by an event.
 */
describe('the outcome of a connect flow', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});
	afterEach(() => {
		resetKeyringForTests(TEST_KEYRING);
		assertNoPendingInterceptors();
	});

	it('stores nothing when the person declines, and says so in their language', async () => {
		const service = await github();
		const { browser, accountId } = await signedInPerson();
		githubStub();
		const authorize = await startConnect(browser, service.id);

		const response = await callback(browser, authorize, {
			error: 'access_denied'
		});
		const page = await browser.request(
			new URL(
				present(response.headers.get('location'), 'the page'),
				ISSUER
			).toString(),
			{ headers: { 'accept-language': 'ru' } }
		);

		expect(textOf(await page.text())).toContain(
			'Аккаунт не подключён: доступ не разрешили.'
		);
		expect(await accountsOf(accountId)).toEqual([]);
	});

	it('stores the scopes the provider granted and shows the ones it did not', async () => {
		const service = await github(['read:user', 'repo']);
		const { browser, accountId } = await signedInPerson();
		const stub = githubStub();
		const authorize = await startConnect(browser, service.id);
		stub.expectToken(githubTokens({ scope: 'read:user' }));
		stub.expectUser({ id: 5, login: 'partial' });

		const text = await landed(browser, await callback(browser, authorize));

		expect(text).toContain('Not allowed: repo');
		expect((await accountsOf(accountId))[0].scopes).toEqual(['read:user']);
	});

	it('refuses an eleventh account at one service, revoking what was issued, and still reconnects an existing one', async () => {
		const service = await github();
		const { browser, accountId, bucket } = await signedInPerson();
		const now = new Date().toISOString();
		for (let n = 1; n <= 10; n += 1) {
			await getConnectedAccountStore().put({
				_id: connectedAccountId(bucket._id, service.id, accountId, String(n)),
				bucketId: bucket._id,
				serviceId: service.id,
				accountId,
				upstreamId: String(n),
				label: `account-${String(n)}`,
				accessToken: unique('gho'),
				tokenType: 'bearer',
				scopes: ['read:user'],
				scopesInferred: false,
				connectedAt: now,
				updatedAt: now
			});
		}
		const stub = githubStub();
		const eleventh = await startConnect(browser, service.id);
		stub.expectToken(githubTokens());
		stub.expectUser({ id: 11, login: 'one-too-many' });
		stub.expectRevoke(service.clientId);
		const refused = await callback(browser, eleventh);
		const again = await startConnect(browser, service.id);
		stub.expectToken(githubTokens());
		stub.expectUser({ id: 3, login: 'account-3-renamed' });

		await landed(browser, await callback(browser, again));

		expect(refused.headers.get('location')).toContain('notice=limit');
		const labels = (await accountsOf(accountId)).map((a) => a.label);
		expect(labels).toHaveLength(10);
		expect(labels).toContain('account-3-renamed');
	});

	it('revokes what was issued and stores nothing when the provider will not say who the account is', async () => {
		const service = await github();
		const { browser, accountId } = await signedInPerson();
		const stub = githubStub();
		const authorize = await startConnect(browser, service.id);
		stub.expectToken(githubTokens());
		stub.expectUser({ message: 'Server Error' }, 500);
		stub.expectRevoke(service.clientId);

		const response = await callback(browser, authorize);

		expect(response.headers.get('location')).toContain('notice=failed');
		expect(await accountsOf(accountId)).toEqual([]);
	});

	it('tells the person the service is unavailable while no keyring is in use, and starts nothing', async () => {
		const service = await github();
		const { browser, accountId } = await signedInPerson();
		const page = await browser.request(
			`${PAGE}?connect=${encodeURIComponent(service.id)}`
		);
		const xsrf = xsrfFrom(await page.text());
		resetKeyringForTests(null);

		const response = await browser.post(PAGE, {
			action: 'connect',
			serviceId: service.id,
			xsrf
		});

		expect(response.headers.get('location')).toContain('notice=unavailable');
		expect(await accountsOf(accountId)).toEqual([]);
	});

	it('refuses a token write while no keyring is in use, so a token is never stored readable', async () => {
		resetKeyringForTests(null);
		const now = new Date().toISOString();

		const write = getConnectedAccountStore().put({
			_id: 'never-plaintext',
			bucketId: 'b',
			serviceId: 's',
			accountId: 'a',
			upstreamId: 'u',
			label: 'l',
			accessToken: 'plaintext-token',
			tokenType: 'bearer',
			scopes: [],
			scopesInferred: true,
			connectedAt: now,
			updatedAt: now
		});

		await expect(write).rejects.toBeInstanceOf(KeyringRequired);
	});

	it('carries no token in any connected-account event of a connect and a disconnect', async () => {
		const service = await github();
		const { browser, accountId } = await signedInPerson();
		const payloads: unknown[] = [];
		const listen = (payload: unknown) => payloads.push(payload);
		const names = [
			'connected_account.connected',
			'connected_account.updated',
			'connected_account.deleted',
			'connected_account.revocation'
		] as const;
		for (const name of names) eventBus.on(name, listen);
		const stub = githubStub();
		const tokens = githubTokens();
		try {
			const authorize = await startConnect(browser, service.id);
			stub.expectToken(tokens);
			stub.expectUser({ id: 8, login: 'evented' });
			await landed(browser, await callback(browser, authorize));
			const [account] = await accountsOf(accountId);
			const confirm = await browser.request(
				`${PAGE}?disconnect=${encodeURIComponent(account._id)}`
			);
			stub.expectRevoke(service.clientId);
			await browser.post(PAGE, {
				action: 'disconnect',
				connectedAccountId: account._id,
				xsrf: xsrfFrom(await confirm.text())
			});
		} finally {
			for (const name of names) eventBus.off(name, listen);
		}

		expect(payloads.length).toBeGreaterThanOrEqual(3);
		const seen = JSON.stringify(payloads);
		expect(seen).not.toContain(tokens.access_token);
		expect(seen).not.toContain(String(tokens.refresh_token));
		expect(seen).not.toContain('evented');
	});
});
