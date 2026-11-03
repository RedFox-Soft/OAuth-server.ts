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
import {
	getConnectedAccountStore,
	getUserStore,
	rawConnectedAccountStoreForTests
} from 'lib/adapters/index.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { eventBus } from 'lib/event_bus.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { SEALED_PREFIX } from 'lib/sealing/seal.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { admin } from '../connected_services/harness.ts';
import { unique } from '../connected_services/stubs.ts';
import {
	get,
	signedInAccountIds,
	startInteraction
} from '../federation/harness.ts';
import { allowAccount, exchange, refused } from '../upstream_tokens/harness.ts';
import {
	SERVICE_ID,
	SERVICE_SCOPES,
	agentFor,
	keptAccounts,
	linkedProject,
	signInThrough,
	upstreamPerson
} from './harness.ts';

const TOKENS = {
	access_token: 'kept-access-token',
	refresh_token: 'kept-refresh-token',
	expires_in: 3600
};

async function keptAtService(): Promise<number> {
	return getConnectedAccountStore().countByService(
		DEFAULT_BUCKET_ID,
		SERVICE_ID
	);
}

function refusals(): { reasons: string[]; stop: () => void } {
	const reasons: string[] = [];
	const listen = (event: { reason: string }) => reasons.push(event.reason);
	eventBus.on('connected_account.refused', listen);
	return {
		reasons,
		stop: () => eventBus.off('connected_account.refused', listen)
	};
}

/**
 * @proves Keeping a sign-in's tokens never stops a person signing in and never keeps a token from a sign-in that did
 * not complete for that person: faults, refusals, pauses and previews keep nothing, and what is kept is sealed and
 * named in no event.
 */
describe('keeping tokens from a sign-in, when something goes wrong', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'signin_tokens' });
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	it('signs the person in, asking for nothing more and keeping nothing, while no keyring is in use', async () => {
		resetKeyringForTests(null);
		const linked = await linkedProject();
		const claims = upstreamPerson();

		const { authorizeUrl, accountId } = await signInThrough(linked, claims);

		expect(signedInAccountIds()).toContain(present(accountId, 'the person'));
		expect(authorizeUrl.searchParams.get('scope')?.split(' ')).not.toContain(
			SERVICE_SCOPES[0]
		);
		expect(await keptAccounts(present(accountId, 'the person'))).toEqual([]);
	});

	it('signs the person in and keeps nothing when they already hold as many accounts as allowed there', async () => {
		const linked = await linkedProject();
		const claims = upstreamPerson();
		const { accountId } = await signInThrough(linked, claims);
		const person = present(accountId, 'the person');
		const store = getConnectedAccountStore();
		const [first] = await keptAccounts(person);
		await store.destroy(DEFAULT_BUCKET_ID, present(first, 'the account')._id);
		for (let index = 0; index < 10; index += 1) {
			await store.put({
				...present(first, 'the account'),
				_id: unique('other-account'),
				upstreamId: unique('other-upstream')
			});
		}
		const watch = refusals();

		try {
			await signInThrough(linked, claims);
		} finally {
			watch.stop();
		}

		const accounts = await keptAccounts(person);
		expect(accounts.map((account) => account.upstreamId)).not.toContain(
			claims.sub
		);
		expect(watch.reasons).toContain('limit');
	});

	it('signs the person in when storing the account fails, and says why', async () => {
		const linked = await linkedProject();
		const claims = upstreamPerson();
		spyOn(getConnectedAccountStore(), 'put').mockRejectedValue(
			new Error('storage down')
		);
		const watch = refusals();

		let accountId: string | undefined;
		try {
			({ accountId } = await signInThrough(linked, claims));
		} finally {
			watch.stop();
		}

		expect(signedInAccountIds()).toContain(present(accountId, 'the person'));
		expect(watch.reasons).toContain('failed');
	});

	it('keeps nothing from a sign-in refused for its address', async () => {
		const linked = await linkedProject({
			provider: { allowedEmailDomains: ['elsewhere.example'] }
		});
		const before = await keptAtService();

		await signInThrough(linked, upstreamPerson());

		expect(await keptAtService()).toBe(before);
	});

	it('keeps nothing from a sign-in refused because the project admits no new people', async () => {
		const linked = await linkedProject({
			provider: { provisioning: 'existing_only' }
		});
		const before = await keptAtService();

		await signInThrough(linked, upstreamPerson());

		expect(await keptAtService()).toBe(before);
	});

	it('keeps nothing from a sign-in that pauses for the password of an existing account', async () => {
		const linked = await linkedProject();
		const claims = upstreamPerson();
		const person = await getUserStore(DEFAULT_BUCKET_ID).create(
			String(claims.email),
			await Bun.password.hash('a-long-password-1'),
			true
		);

		const { complete } = await signInThrough(linked, claims);

		expect(complete?.location).toContain('/login');
		expect(await keptAccounts(person._id)).toEqual([]);
	});

	it('asks for nothing more in a console preview of the provider', async () => {
		const linked = await linkedProject();
		const cookie = await cookieFor(await createAdministrator('super'));

		const started = await admin(
			cookie,
			'POST',
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/federation/${linked.provider.id}/try`
		);

		const asked = new URL(String(started.json.authorizationUrl)).searchParams
			.get('scope')
			?.split(' ');
		expect(asked).not.toContain(SERVICE_SCOPES[0]);
	});

	it('keeps tokens under the person the sign-in completed for, each their own', async () => {
		const linked = await linkedProject();
		const alice = upstreamPerson();
		const bob = upstreamPerson();

		const first = await signInThrough(linked, alice);
		const second = await signInThrough(linked, bob);

		const aliceAccounts = await keptAccounts(present(first.accountId, 'Alice'));
		const bobAccounts = await keptAccounts(present(second.accountId, 'Bob'));
		expect(aliceAccounts.map((account) => account.upstreamId)).toEqual([
			String(alice.sub)
		]);
		expect(bobAccounts.map((account) => account.upstreamId)).toEqual([
			String(bob.sub)
		]);
	});

	it('keeps nothing when the sign-in’s handoff is spent in another interaction', async () => {
		const linked = await linkedProject();
		const claims = upstreamPerson();
		const mine = await startInteraction('keep-app');
		const theirs = await startInteraction('keep-app');
		const start = await get(
			`/ui/${mine.uid}/federation/${linked.provider.id}/start`,
			mine.cookie
		);
		const authorizeUrl = new URL(start.location);
		await linked.idp.answerToken(authorizeUrl, claims, {}, TOKENS);
		const callback = await get(
			`/federation/callback?${new URLSearchParams({
				code: 'upstream-code',
				state: authorizeUrl.searchParams.get('state') ?? ''
			}).toString()}`
		);
		const ref = new URL(callback.location, 'http://e.ly').searchParams.get(
			'ref'
		);
		const before = await keptAtService();

		await get(
			`/ui/${theirs.uid}/federation/complete?ref=${ref ?? ''}`,
			theirs.cookie
		);

		expect(await keptAtService()).toBe(before);
	});

	it('refuses an agent a scope the person did not grant at sign-in, asking for a reconnect', async () => {
		const linked = await linkedProject();
		const { accountId } = await signInThrough(linked, upstreamPerson(), {
			...TOKENS,
			scope: `openid email profile ${SERVICE_SCOPES[0]}`
		});
		const person = present(accountId, 'the person');
		const signedIn = await agentFor(setup, person);
		const [account] = await keptAccounts(person);
		await allowAccount(signedIn.grantId, present(account, 'the account'));

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: linked.service.id,
				scope: SERVICE_SCOPES[1]
			})
		);

		expect(body.reason).toBe('reconnect_required');
	});

	it('stores the kept tokens sealed and names none of them in an event', async () => {
		const linked = await linkedProject();
		const seen: unknown[] = [];
		const listen = (event: unknown) => seen.push(event);
		const names = [
			'connected_account.connected',
			'connected_account.updated',
			'connected_account.refused',
			'federation.keep.retried'
		] as const;
		for (const name of names) eventBus.on(name, listen);
		let accountId: string | undefined;
		try {
			({ accountId } = await signInThrough(linked, upstreamPerson()));
		} finally {
			for (const name of names) eventBus.off(name, listen);
		}

		const [account] = await keptAccounts(present(accountId, 'the person'));
		const raw = await rawConnectedAccountStoreForTests().find(
			DEFAULT_BUCKET_ID,
			present(account, 'the account')._id
		);
		expect(raw?.accessToken?.startsWith(SEALED_PREFIX)).toBe(true);
		expect(raw?.refreshToken?.startsWith(SEALED_PREFIX)).toBe(true);
		expect(JSON.stringify(seen)).not.toContain('kept-');
	});
});
