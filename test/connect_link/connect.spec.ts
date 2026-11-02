import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock,
	setSystemTime
} from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ACCOUNTS_PER_SERVICE } from 'lib/connected_services/accounts.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { Browser } from '../connected_apps/helpers.ts';
import { accountsOf, callback } from '../connected_services/harness.ts';
import {
	githubStub,
	githubTokens,
	unique
} from '../connected_services/stubs.ts';
import {
	connected,
	exchange,
	githubService,
	granted,
	refused
} from '../upstream_tokens/harness.ts';
import {
	act,
	linkFor,
	locationOf,
	personAndAgent,
	read,
	signInFrom
} from './harness.ts';

/**
 * @proves A person with no account at a service, sent a link by an agent whose exchange was refused, connects the
 * account through it after a sign-in of their own, and the agent's next exchange succeeds; a person who declines at
 * the provider changes nothing and can try again.
 */
describe('connecting a service from an agent’s link', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'connect_link' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	afterEach(() => {
		setSystemTime();
		assertNoPendingInterceptors();
		mock.restore();
	});

	/* Presses the link's button and answers where the provider sends the person, with the provider's answers set up. */
	async function connectThrough(browser: Browser, path: string, id = 583231) {
		const github = githubStub();
		const pressed = await act(browser, path, { action: 'connect' });
		expect(pressed.status).toBe(303);
		const tokens = githubTokens();
		github.expectToken(tokens);
		github.expectUser({ id, login: unique('octocat') });
		return { back: await callback(browser, locationOf(pressed)), tokens };
	}

	it('carries a link, its identifier, its lifetime and a sentence when the person has no account', async () => {
		const service = await githubService();
		const { signedIn } = await personAndAgent(setup);

		const { body } = await linkFor(signedIn, service);

		expect(body).toMatchObject({
			error: 'invalid_grant',
			reason: 'connect_required'
		});
		expect(body.connect_uri).toStartWith('http');
		expect(body.connect_id).toBeString();
		expect(body.connect_expires_in).toBeGreaterThan(1700);
		expect(body.connect_expires_in).toBeLessThanOrEqual(1800);
		expect(body.connect_message).toContain('GitHub');
	});

	it('connects the account, allows the agent and lets its next exchange succeed', async () => {
		const service = await githubService();
		const { browser, signedIn } = await personAndAgent(setup);
		const { path } = await linkFor(signedIn, service);

		const page = await read(browser, path);
		expect(page.status).toBe(200);
		expect(page.text).toContain('Connect GitHub and allow');
		const { tokens } = await connectThrough(browser, path);

		const body = granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);
		expect(body.access_token).toBe(tokens.access_token);
	});

	it('tells the person they can return to the agent once connected', async () => {
		const service = await githubService();
		const { browser, signedIn } = await personAndAgent(setup);
		const { path } = await linkFor(signedIn, service);

		const { back } = await connectThrough(browser, path);
		const landed = await read(browser, locationOf(back).toString());

		expect(landed.text).toContain('can use it');
		expect(landed.text).toContain('You can return to');
	});

	it('connects nothing when the person declines at the provider, and the link still works', async () => {
		const service = await githubService();
		const { browser, signedIn, accountId } = await personAndAgent(setup);
		const { path } = await linkFor(signedIn, service);
		const pressed = await act(browser, path, { action: 'connect' });

		const back = await callback(browser, locationOf(pressed), {
			error: 'access_denied'
		});
		const landed = await read(browser, locationOf(back).toString());

		expect(await accountsOf(accountId)).toHaveLength(0);
		expect(landed.text).toContain('try again from this link');
		expect(landed.text).toContain('Connect GitHub and allow');
	});

	it('sends a person who is not signed in to sign in, and back to the same link', async () => {
		const service = await githubService();
		const { signedIn, email } = await personAndAgent(setup);
		const { path } = await linkFor(signedIn, service);

		const landed = await signInFrom(new Browser(), path, email);

		expect(new URL(landed.url).pathname).toBe(path);
		expect(landed.text).toContain('Connect GitHub and allow');
	});

	it('asks a person whose sign-in is older than fifteen minutes to sign in again, and returns to the link', async () => {
		const service = await githubService();
		const { browser, signedIn, email } = await personAndAgent(setup);
		const { path } = await linkFor(signedIn, service);
		setSystemTime(new Date(Date.now() + 16 * 60 * 1000));

		const landed = await signInFrom(browser, path, email);

		expect(new URL(landed.url).pathname).toBe(path);
		expect(landed.text).toContain('Connect GitHub and allow');
	});

	it('writes the sentence in the person’s stored language', async () => {
		const service = await githubService();
		const { signedIn, accountId } = await personAndAgent(setup);
		await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
			profile: { locale: 'ru' }
		});

		const { body } = await linkFor(signedIn, service);

		expect(body.connect_message).toContain('Откройте эту ссылку');
	});

	it('offers a person at the per-service limit their existing accounts instead', async () => {
		const service = await githubService();
		const { browser, signedIn, accountId } = await personAndAgent(setup);
		for (let i = 0; i < ACCOUNTS_PER_SERVICE; i += 1) {
			await connected(accountId, service);
		}
		const { path } = await linkFor(signedIn, service, { loginHint: 'nobody' });

		const page = await read(browser, path);

		expect(page.text).toContain('as many GitHub accounts as you can');
		expect(page.text).not.toContain('Connect another GitHub account');
	});

	it('records no consent when the administrator withdrew the agent while the person was at the provider', async () => {
		const service = await githubService();
		const { browser, signedIn } = await personAndAgent(setup);
		const { path } = await linkFor(signedIn, service);
		const pressed = await act(browser, path, { action: 'connect' });
		const bucket = present(
			await getBucketStore().find(DEFAULT_BUCKET_ID),
			'the project'
		);
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			connectedServices: (bucket.connectedServices ?? []).map((item) =>
				item.id === service.id ? { ...item, applications: [] } : item
			)
		});
		const github = githubStub();
		github.expectToken(githubTokens());
		github.expectUser({ id: 77, login: unique('octocat') });

		await callback(browser, locationOf(pressed));
		await getBucketStore().update(DEFAULT_BUCKET_ID, {
			connectedServices: bucket.connectedServices ?? []
		});

		expect(
			refused(
				await exchange({
					subjectToken: signedIn.accessToken,
					audience: service.id
				})
			).reason
		).toBe('consent_required');
	});
});
