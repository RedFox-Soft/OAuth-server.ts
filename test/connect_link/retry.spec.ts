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
import { adminAuditStore } from 'lib/adapters/index.ts';
import { eventBus } from 'lib/event_bus.js';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { githubStub, unique } from '../connected_services/stubs.ts';
import epochTime from 'lib/helpers/epoch_time.js';
import {
	allowAccount,
	connected,
	exchange,
	githubService,
	granted
} from '../upstream_tokens/harness.ts';
import { act, linkFor, personAndAgent, refusedWith } from './harness.ts';

const EVENTS = [
	'connect_link.issued',
	'connect_link.completed',
	'connect_link.declined',
	'connect_link.refused',
	'connected_account.consent'
] as const;

/**
 * @proves An agent retrying while the person is busy receives one link and one identifier for as long as the link
 * lives, a fresh one once it was used or replaced, and none for a refusal the person cannot fix; the link's value, an
 * upstream token and an account label appear in no event or audit record.
 */
describe('an agent retrying the exchange', () => {
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

	it('receives the same link and identifier until the refusal changes', async () => {
		const service = await githubService();
		const owner = await personAndAgent(setup);

		const first = await linkFor(owner.signedIn, service);
		const second = await linkFor(owner.signedIn, service);
		await connected(owner.accountId, service);
		const changed = await linkFor(owner.signedIn, service);

		expect(second.body.connect_uri).toBe(first.body.connect_uri);
		expect(second.body.connect_id).toBe(first.body.connect_id);
		expect(changed.body.reason).toBe('consent_required');
		expect(changed.body.connect_uri).not.toBe(first.body.connect_uri);
		expect(changed.body.connect_id).not.toBe(first.body.connect_id);
	});

	it('is answered from the current state once the link was used, and given a fresh link once it was declined', async () => {
		const service = await githubService();
		const owner = await personAndAgent(setup);
		const record = await connected(owner.accountId, service);
		const declined = await linkFor(owner.signedIn, service);
		await act(owner.browser, declined.path, { action: 'decline' });

		const fresh = await linkFor(owner.signedIn, service);
		await act(owner.browser, fresh.path, {
			action: 'allow',
			connectedAccountId: record._id
		});

		expect(fresh.body.connect_id).not.toBe(declined.body.connect_id);
		granted(
			await exchange({
				subjectToken: owner.signedIn.accessToken,
				audience: service.id
			})
		);
	});

	it('is refused as not permitted, with no link, for a scope the service does not declare', async () => {
		const service = await githubService();
		const owner = await personAndAgent(setup);
		await allowAccount(
			owner.signedIn.grantId,
			await connected(owner.accountId, service)
		);

		const body = refusedWith(
			await exchange({
				subjectToken: owner.signedIn.accessToken,
				audience: service.id,
				scope: 'admin:org'
			})
		);

		expect(body).toMatchObject({
			error: 'invalid_scope',
			reason: 'not_permitted'
		});
		expect(body.error_description).toContain('admin:org');
		expect(body.connect_uri).toBeUndefined();
	});

	it('carries no link when the administrator did not allow the application', async () => {
		const service = await githubService(['other-agent']);
		const owner = await personAndAgent(setup);

		const body = refusedWith(
			await exchange({
				subjectToken: owner.signedIn.accessToken,
				audience: service.id
			})
		);

		expect(body.reason).toBe('not_permitted');
		expect(body.connect_uri).toBeUndefined();
	});

	it('carries no link while the provider cannot be reached', async () => {
		const service = await githubService();
		const owner = await personAndAgent(setup);
		await allowAccount(
			owner.signedIn.grantId,
			await connected(owner.accountId, service, {
				accessTokenExpiresAt: epochTime() - 10
			})
		);
		githubStub().expectRefreshUnavailable();

		const body = refusedWith(
			await exchange({
				subjectToken: owner.signedIn.accessToken,
				audience: service.id
			}),
			503
		);

		expect(body.connect_uri).toBeUndefined();
	});

	it('carries no link for a subject token it cannot read', async () => {
		const service = await githubService();

		const body = refusedWith(
			await exchange({ subjectToken: unique('forged'), audience: service.id })
		);

		expect(body.connect_uri).toBeUndefined();
	});

	it('leaves the link’s value, tokens and labels out of every event and audit record', async () => {
		const service = await githubService();
		const owner = await personAndAgent(setup);
		const record = await connected(owner.accountId, service);
		const seen: unknown[] = [];
		for (const name of EVENTS) {
			eventBus.on(name, (event: unknown) => seen.push(event));
		}
		let value: string;
		try {
			const { path } = await linkFor(owner.signedIn, service);
			value = present(path.split('/').at(-1), 'the value');
			await act(owner.browser, path, {
				action: 'allow',
				connectedAccountId: record._id
			});
		} finally {
			for (const name of EVENTS) eventBus.removeAllListeners(name);
		}
		const { entries } = await adminAuditStore.list({
			targetId: owner.accountId
		});

		const text = JSON.stringify([seen, entries]);
		expect(seen.length).toBeGreaterThanOrEqual(3);
		for (const secret of [
			value,
			record.label,
			present(record.accessToken, 'a token'),
			owner.signedIn.accessToken
		]) {
			expect(text).not.toContain(secret);
		}
	});
});
