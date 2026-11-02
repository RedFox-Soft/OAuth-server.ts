import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { forgetAllDiscovery } from 'lib/federation/discovery.ts';
import { SEALED_PREFIX } from 'lib/sealing/seal.ts';
import {
	accountsOf,
	addService,
	callback,
	landed,
	signedInPerson,
	startConnect
} from './harness.ts';
import {
	githubStub,
	githubTokens,
	oidcStub,
	slackStub,
	slackTokens,
	unique
} from './stubs.ts';

/**
 * @proves A person connects an account at a service their project declared, and the account is stored with its
 * tokens sealed, the scopes granted, the token's expiry and who the account is at the provider.
 */
describe('a signed-in person connecting an account', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});
	beforeEach(() => {
		forgetAllDiscovery();
	});
	afterEach(() => {
		assertNoPendingInterceptors();
	});

	it('stores a GitHub account with sealed tokens, granted scopes, expiry and its GitHub id', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github',
			scopes: ['read:user'],
			displayName: 'GitHub'
		});
		const { browser, accountId } = await signedInPerson();
		const github = githubStub();
		const authorize = await startConnect(browser, service.id);
		github.expectToken(githubTokens());
		github.expectUser({ id: 583231, login: 'octocat' });

		const text = await landed(browser, await callback(browser, authorize));

		expect(text).toContain('Your GitHub account is connected.');
		const [stored] = await accountsOf(accountId);
		expect(stored).toMatchObject({
			upstreamId: '583231',
			label: 'octocat',
			scopes: ['read:user'],
			scopesInferred: false
		});
		expect(stored.accessToken?.startsWith(SEALED_PREFIX)).toBe(true);
		expect(stored.refreshToken?.startsWith(SEALED_PREFIX)).toBe(true);
		expect(stored.accessTokenExpiresAt).toBeGreaterThan(Date.now() / 1000);
	});

	it('stores a Slack account under its workspace and user, from the token answer', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'slack',
			scopes: ['users:read', 'chat:write']
		});
		const { browser, accountId } = await signedInPerson();
		const slack = slackStub();
		const authorize = await startConnect(browser, service.id);
		slack.expectToken(slackTokens('T0042', 'U0042'));

		await landed(browser, await callback(browser, authorize));

		const [stored] = await accountsOf(accountId);
		expect(stored).toMatchObject({
			upstreamId: 'T0042:U0042',
			label: 'Acme Workspace',
			scopes: ['users:read', 'chat:write']
		});
	});

	it('stores a Google account under the subject of its verified ID token', async () => {
		const google = await oidcStub('https://accounts.google.com', {
			clientId: 'google-client'
		});
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'google',
			clientId: 'google-client',
			scopes: ['https://www.googleapis.com/auth/gmail.readonly']
		});
		const { browser, accountId } = await signedInPerson();
		google.expectDiscovery();
		const authorize = await startConnect(browser, service.id);
		await google.answerToken(
			authorize,
			{ sub: '1092837465', email: 'person@gmail.test' },
			{
				access_token: unique('ya29'),
				refresh_token: unique('1//refresh'),
				expires_in: 3599,
				token_type: 'Bearer',
				scope: 'openid email https://www.googleapis.com/auth/gmail.readonly'
			}
		);

		await landed(browser, await callback(browser, authorize));

		const [stored] = await accountsOf(accountId);
		expect(stored).toMatchObject({
			upstreamId: '1092837465',
			label: 'person@gmail.test'
		});
		expect(stored.refreshToken?.startsWith(SEALED_PREFIX)).toBe(true);
	});

	it('stores a Microsoft account under its directory and object id', async () => {
		const tenant = '72f988bf-86f1-41af-91ab-2d7cd011db47';
		const microsoft = await oidcStub('https://login.microsoftonline.com', {
			clientId: 'ms-client',
			issuerPath: `/${tenant}/v2.0`
		});
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'microsoft',
			tenant,
			clientId: 'ms-client',
			scopes: ['User.Read']
		});
		const { browser, accountId } = await signedInPerson();
		microsoft.expectDiscovery();
		const authorize = await startConnect(browser, service.id);
		await microsoft.answerToken(
			authorize,
			{
				tid: tenant,
				oid: 'b5d3f9a1-0000-4000-8000-000000000001',
				preferred_username: 'person@contoso.test'
			},
			{
				access_token: unique('eyJ0eXAi'),
				refresh_token: unique('M.R3_BAY'),
				expires_in: 4510,
				token_type: 'Bearer',
				scope: 'User.Read openid profile offline_access'
			}
		);

		await landed(browser, await callback(browser, authorize));

		const [stored] = await accountsOf(accountId);
		expect(stored).toMatchObject({
			upstreamId: `${tenant}:b5d3f9a1-0000-4000-8000-000000000001`,
			label: 'person@contoso.test'
		});
	});

	it('replaces the tokens of an upstream account connected again, without a second record', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github',
			scopes: ['read:user']
		});
		const { browser, accountId } = await signedInPerson();
		const github = githubStub();
		for (let attempt = 0; attempt < 2; attempt += 1) {
			const authorize = await startConnect(browser, service.id);
			github.expectToken(githubTokens());
			github.expectUser({ id: 7, login: 'same-person' });
			await landed(browser, await callback(browser, authorize));
		}
		const stored = await accountsOf(accountId);
		expect(stored).toHaveLength(1);
	});

	it('keeps a different upstream account at the same service as a second account', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github',
			scopes: ['read:user']
		});
		const { browser, accountId } = await signedInPerson();
		const github = githubStub();
		for (const id of [11, 12]) {
			const authorize = await startConnect(browser, service.id);
			github.expectToken(githubTokens());
			github.expectUser({ id, login: `login-${String(id)}` });
			await landed(browser, await callback(browser, authorize));
		}
		const labels = (await accountsOf(accountId)).map((a) => a.label).sort();
		expect(labels).toEqual(['login-11', 'login-12']);
	});

	it('stores an account whose provider issues no refresh token as not expiring', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github',
			scopes: ['read:user']
		});
		const { browser, accountId } = await signedInPerson();
		const github = githubStub();
		const authorize = await startConnect(browser, service.id);
		github.expectToken(githubTokens({ refresh: false }));
		github.expectUser({ id: 99, login: 'classic-app' });

		await landed(browser, await callback(browser, authorize));

		const [stored] = await accountsOf(accountId);
		expect(stored.refreshToken).toBeUndefined();
		expect(stored.accessTokenExpiresAt).toBeUndefined();
	});
});
