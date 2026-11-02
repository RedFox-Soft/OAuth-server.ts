import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { getBucketStore } from 'lib/adapters/index.ts';
import { forgetAllDiscovery } from 'lib/federation/discovery.ts';
import { Browser, signInThroughPage } from '../connected_apps/helpers.ts';
import {
	accountsOf,
	addService,
	callback,
	signedInPerson,
	startConnect
} from './harness.ts';
import { githubStub, githubTokens, oidcStub, unique } from './stubs.ts';

async function github() {
	return addService({
		kind: 'catalogue',
		catalogueId: 'github',
		scopes: ['read:user']
	});
}

/**
 * @proves A connect flow finishes only in the session, for the person and in the project that started it, once
 * and in time, so nobody can make a person's record hold another person's upstream account or the reverse.
 */
describe('a provider answer arriving at the connect callback', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});
	beforeEach(() => {
		forgetAllDiscovery();
	});
	afterEach(() => {
		setSystemTime();
		// Every refusal below must stop before the token request: no interceptor is registered for one.
		assertNoPendingInterceptors();
	});

	it('stores nothing when it arrives in a browser without the session that started the flow', async () => {
		const service = await github();
		const victim = await signedInPerson();
		const authorize = await startConnect(victim.browser, service.id);
		githubStub();

		const response = await callback(new Browser(), authorize);

		expect(response.status).toBe(403);
		expect(await accountsOf(victim.accountId)).toEqual([]);
	});

	it('stores nothing when the browser session has become another person’s', async () => {
		const service = await github();
		const first = await signedInPerson();
		const authorize = await startConnect(first.browser, service.id);
		const second = await signedInPerson();
		// The same browser: the first person signs out and the second signs in.
		first.browser.forget('_session_default');
		await signInThroughPage(first.browser, second.email);
		githubStub();

		const response = await callback(first.browser, authorize);

		expect(response.status).toBe(403);
		expect(await accountsOf(first.accountId)).toEqual([]);
		expect(await accountsOf(second.accountId)).toEqual([]);
	});

	it('refuses an answer replayed after the flow completed', async () => {
		const service = await github();
		const { browser, accountId } = await signedInPerson();
		const stub = githubStub();
		const authorize = await startConnect(browser, service.id);
		stub.expectToken(githubTokens());
		stub.expectUser({ id: 1, login: 'once' });
		const code = unique('code');
		await callback(browser, authorize, { code });

		const replay = await callback(browser, authorize, { code });

		expect(replay.status).toBe(400);
		expect(await accountsOf(accountId)).toHaveLength(1);
	});

	it('refuses an answer arriving after the flow expired', async () => {
		const service = await github();
		const { browser, accountId } = await signedInPerson();
		const authorize = await startConnect(browser, service.id);
		setSystemTime(new Date(Date.now() + 11 * 60 * 1000));
		githubStub();

		const response = await callback(browser, authorize);

		expect(response.status).toBe(400);
		expect(await accountsOf(accountId)).toEqual([]);
	});

	it('refuses a state this server never issued', async () => {
		const { browser } = await signedInPerson();
		const forged = new URL('https://github.com/login/oauth/authorize');
		forged.searchParams.set('state', unique('forged'));

		const response = await callback(browser, forged);

		expect(response.status).toBe(400);
	});

	it('refuses an answer presented at another project', async () => {
		const service = await github();
		const { browser, accountId } = await signedInPerson();
		const authorize = await startConnect(browser, service.id);
		const other = await getBucketStore().create({
			name: unique('other'),
			slug: unique('other')
				.toLowerCase()
				.replace(/[^a-z0-9-]/g, ''),
			ownerGroupId: 'unassigned'
		});
		githubStub();
		const params = new URLSearchParams({
			state: authorize.searchParams.get('state') ?? '',
			code: unique('code')
		});

		const response = await browser.request(
			`/${String(other.slug)}/account/services/callback?${params.toString()}`
		);

		expect(response.status).toBe(403);
		expect(await accountsOf(accountId)).toEqual([]);
	});

	it('stores nothing for a service deleted while the flow was at the provider', async () => {
		const service = await github();
		const { browser, accountId, bucket } = await signedInPerson();
		const authorize = await startConnect(browser, service.id);
		const current = await getBucketStore().find(bucket._id);
		await getBucketStore().update(bucket._id, {
			connectedServices: (current?.connectedServices ?? []).filter(
				(item) => item.id !== service.id
			)
		});
		githubStub();

		const response = await callback(browser, authorize);

		expect(response.status).toBe(303);
		expect(response.headers.get('location')).toContain('notice=unavailable');
		expect(await accountsOf(accountId)).toEqual([]);
	});

	it('refuses an authorization answer whose issuer is not the provider’s', async () => {
		const idp = await oidcStub('https://idp-connected-iss.test', {
			clientId: 'iss-client',
			issParameterSupported: true
		});
		const service = await addService({
			kind: 'oidc',
			issuer: idp.issuer,
			clientId: 'iss-client',
			scopes: ['openid']
		});
		const { browser, accountId } = await signedInPerson();
		idp.expectDiscovery();
		const authorize = await startConnect(browser, service.id);

		const response = await callback(browser, authorize, {
			code: unique('code'),
			iss: 'https://attacker.test'
		});

		expect(response.headers.get('location')).toContain('notice=refused');
		expect(await accountsOf(accountId)).toEqual([]);
	});
});
