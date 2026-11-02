import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock
} from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import { getConnectedAccountStore } from 'lib/adapters/index.ts';
import epochTime from 'lib/helpers/epoch_time.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { callback } from '../connected_services/harness.ts';
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
	refused
} from '../upstream_tokens/harness.ts';
import { act, linkFor, locationOf, personAndAgent, read } from './harness.ts';

/**
 * @proves A person whose account an agent can no longer use, because the provider stopped accepting it or it lacks a
 * scope the service declares, reconnects it from the agent's link and keeps every consent it had; connecting a
 * different upstream account instead connects that one, without consent, and leaves the broken one as it was.
 */
describe('reconnecting an account from an agent’s link', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'connect_link' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	async function brokenAccount() {
		const service = await githubService();
		const owner = await personAndAgent(setup);
		const upstreamId = String(5000 + Math.floor(Math.random() * 1000));
		const record = await connected(owner.accountId, service, {
			upstreamId,
			broken: { reason: 'refresh_rejected', at: epochTime(), notified: true }
		});
		await allowAccount(owner.signedIn.grantId, record);
		const { body, path } = await linkFor(owner.signedIn, service);
		return { service, owner, record, upstreamId, body, path };
	}

	async function reconnectAs(
		owner: Awaited<ReturnType<typeof personAndAgent>>,
		path: string,
		id: number
	) {
		const github = githubStub();
		const pressed = await act(owner.browser, path, { action: 'connect' });
		github.expectToken(githubTokens({ scope: 'repo,read:user' }));
		github.expectUser({ id, login: unique('octocat') });
		const back = await callback(owner.browser, locationOf(pressed));
		return read(owner.browser, locationOf(back).toString());
	}

	it('makes the broken account usable again with its consents kept', async () => {
		const { service, owner, record, upstreamId, body, path } =
			await brokenAccount();
		expect(body.reason).toBe('reconnect_required');
		expect((await read(owner.browser, path)).text).toContain(record.label);

		const done = await reconnectAs(owner, path, Number(upstreamId));

		expect(done.text).toContain('works again');
		granted(
			await exchange({
				subjectToken: owner.signedIn.accessToken,
				audience: service.id
			})
		);
	});

	it('connects another upstream account without consent and leaves the broken one', async () => {
		const { service, owner, path } = await brokenAccount();

		const done = await reconnectAs(owner, path, 999_999);

		expect(done.text).toContain('Another GitHub account was connected');
		expect(
			refused(
				await exchange({
					subjectToken: owner.signedIn.accessToken,
					audience: service.id
				})
			).reason
		).toBe('reconnect_required');
	});

	it('asks the provider for the declared scopes when the account lacks one', async () => {
		const service = await githubService();
		const owner = await personAndAgent(setup);
		const record = await connected(owner.accountId, service, {
			scopes: ['read:user']
		});
		await allowAccount(owner.signedIn.grantId, record);
		const { body, path } = await linkFor(owner.signedIn, service, {
			scope: 'repo'
		});
		expect(body.reason).toBe('reconnect_required');

		const pressed = await act(owner.browser, path, { action: 'connect' });

		const asked = new Set(
			(locationOf(pressed).searchParams.get('scope') ?? '').split(/[ ,]/)
		);
		expect(asked.has('repo')).toBe(true);
		expect(asked.has('read:user')).toBe(true);
	});

	it('says it is already done when the account was reconnected on the account page', async () => {
		const { owner, record, path } = await brokenAccount();
		const { broken: _broken, ...repaired } = record;
		await getConnectedAccountStore().put(repaired);

		const page = await read(owner.browser, path);

		expect(page.text).toContain('already done');
	});
});
