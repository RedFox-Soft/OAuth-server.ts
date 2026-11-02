import crypto from 'node:crypto';
import {
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { getBucketStore } from 'lib/adapters/index.ts';
import { xsrfFrom } from '../connected_apps/helpers.ts';
import { present } from '../shape.ts';
import {
	accountsOf,
	addService,
	callback,
	landed,
	PAGE,
	postConnect,
	signedInPerson,
	startConnect
} from './harness.ts';
import { githubStub, githubTokens, slackStub, slackTokens } from './stubs.ts';

function isProviderRedirect(response: Response): boolean {
	const location = response.headers.get('location') ?? '';
	return response.status === 303 && location.startsWith('https://');
}

/**
 * @proves A connect flow starts only from the person's own action on their account page, after a recent sign-in,
 * and its code can be redeemed only with the verifier this flow holds.
 */
describe('starting a connect flow', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});
	afterEach(() => {
		setSystemTime();
		assertNoPendingInterceptors();
	});

	it('starts no flow for a request sent from another site', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github'
		});
		const { browser } = await signedInPerson();

		const response = await postConnect(browser, service.id, {
			'sec-fetch-site': 'cross-site',
			origin: 'https://evil.example.net'
		});

		expect(response.status).toBe(403);
		expect(isProviderRedirect(response)).toBe(false);
	});

	it('lets the connect confirmation hand off to the provider and to nowhere else', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github'
		});
		const { browser } = await signedInPerson();

		const page = await browser.request(
			`${PAGE}?connect=${encodeURIComponent(service.id)}`
		);

		/*
		 * A browser holds a form's whole redirect chain to `form-action`: without the provider's origin here, the
		 * person's own Continue is blocked after the server has already answered with the provider's address.
		 */
		const policy = page.headers.get('content-security-policy') ?? '';
		const formAction = /form-action ([^;]+)/
			.exec(policy)?.[1]
			.trim()
			.split(/\s+/);
		expect(formAction?.sort()).toEqual(["'self'", 'https://github.com']);
		expect(page.headers.get('x-frame-options')).toBe('DENY');
	});

	it('starts no flow without the page’s anti-forgery value', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github'
		});
		const { browser } = await signedInPerson();

		const response = await browser.post(PAGE, {
			action: 'connect',
			serviceId: service.id
		});

		expect(response.status).toBe(403);
	});

	it('redeems the code with the verifier whose challenge the provider was sent', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github',
			scopes: ['read:user']
		});
		const { browser, accountId } = await signedInPerson();
		const stub = githubStub();
		const authorize = await startConnect(browser, service.id);
		const challenge = present(
			authorize.searchParams.get('code_challenge'),
			'a challenge'
		);
		stub.expectToken(githubTokens(), (form) => {
			const verifier = new URLSearchParams(form).get('code_verifier') ?? '';
			return (
				crypto.createHash('sha256').update(verifier).digest('base64url') ===
				challenge
			);
		});
		stub.expectUser({ id: 31, login: 'pkce' });

		await landed(browser, await callback(browser, authorize));

		expect(authorize.searchParams.get('code_challenge_method')).toBe('S256');
		expect(await accountsOf(accountId)).toHaveLength(1);
	});

	it('sends Slack no code challenge, which would make its app public', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'slack',
			scopes: ['users:read']
		});
		const { browser } = await signedInPerson();
		const stub = slackStub();
		const authorize = await startConnect(browser, service.id);
		stub.expectToken(
			slackTokens(),
			(form) => !new URLSearchParams(form).has('code_verifier')
		);

		await landed(browser, await callback(browser, authorize));

		expect(authorize.searchParams.has('code_challenge')).toBe(false);
		expect(authorize.searchParams.get('user_scope')).toBe('users:read');
	});

	it('asks for a new sign-in before connecting when the last one is older than fifteen minutes', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github'
		});
		const { browser } = await signedInPerson();
		const page = await browser.request(
			`${PAGE}?connect=${encodeURIComponent(service.id)}`
		);
		const xsrf = xsrfFrom(await page.text());
		setSystemTime(new Date(Date.now() + 16 * 60 * 1000));

		const response = await browser.post(PAGE, {
			action: 'connect',
			serviceId: service.id,
			xsrf
		});

		expect(isProviderRedirect(response)).toBe(false);
		const location = new URL(
			present(response.headers.get('location'), 'a sign-in'),
			'http://x'
		);
		expect(location.pathname.endsWith('/auth')).toBe(true);
		expect(location.searchParams.get('prompt')).toBe('login');
	});

	it('asks for a new sign-in before disconnecting when the last one is older than fifteen minutes', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github',
			scopes: ['read:user']
		});
		const { browser, accountId } = await signedInPerson();
		const stub = githubStub();
		const authorize = await startConnect(browser, service.id);
		stub.expectToken(githubTokens());
		stub.expectUser({ id: 77, login: 'kept' });
		await landed(browser, await callback(browser, authorize));
		const [account] = await accountsOf(accountId);
		const page = await browser.request(
			`${PAGE}?disconnect=${encodeURIComponent(account._id)}`
		);
		const xsrf = xsrfFrom(await page.text());
		setSystemTime(new Date(Date.now() + 16 * 60 * 1000));

		const response = await browser.post(PAGE, {
			action: 'disconnect',
			connectedAccountId: account._id,
			xsrf
		});

		const location = new URL(
			present(response.headers.get('location'), 'a sign-in'),
			'http://x'
		);
		expect(location.searchParams.get('prompt')).toBe('login');
		expect(await accountsOf(accountId)).toHaveLength(1);
	});

	it('makes connecting unavailable in a project scheduled for deletion', async () => {
		const service = await addService({
			kind: 'catalogue',
			catalogueId: 'github'
		});
		const { browser, bucket } = await signedInPerson();
		const page = await browser.request(
			`${PAGE}?connect=${encodeURIComponent(service.id)}`
		);
		const xsrf = xsrfFrom(await page.text());
		await getBucketStore().scheduleDeletion(bucket._id, {
			scheduledAt: new Date(),
			purgeAt: new Date(Date.now() + 30 * 24 * 3600 * 1000),
			scheduledBy: { userId: 'test' }
		});

		const response = await browser.post(PAGE, {
			action: 'connect',
			serviceId: service.id,
			xsrf
		});

		expect(isProviderRedirect(response)).toBe(false);
		await getBucketStore().cancelDeletion(bucket._id, new Date());
	});
});
