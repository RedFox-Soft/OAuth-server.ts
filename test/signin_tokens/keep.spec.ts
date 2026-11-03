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
import { emailsTo } from '../mail_capture.ts';
import { getConnectedAccountStore } from 'lib/adapters/index.ts';
import { eventBus } from 'lib/event_bus.ts';
import epochTime from 'lib/helpers/epoch_time.js';
import { keepRequest } from 'lib/connected_services/link_signin.ts';
import type { ConnectedService } from 'lib/connected_services/types.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import {
	allowAccount,
	exchange,
	granted,
	refused
} from '../upstream_tokens/harness.ts';
import {
	SERVICE_SCOPES,
	agentFor,
	keptAccounts,
	linkedProject,
	signInThrough,
	upstreamPerson
} from './harness.ts';

function scopesAsked(url: URL): string[] {
	return (url.searchParams.get('scope') ?? '').split(' ').filter(Boolean);
}

function catalogueService(
	catalogueId: 'google' | 'microsoft' | 'github',
	scopes: string[]
): ConnectedService {
	return {
		id: `svc-${catalogueId}`,
		kind: 'catalogue',
		catalogueId,
		clientId: 'client',
		scopes,
		displayName: catalogueId,
		createdAt: '',
		updatedAt: ''
	};
}

/**
 * @proves A person who signs in through a sign-in provider linked to a connected service has their account at that
 * service connected by the sign-in itself, with what the provider granted, and an agent still obtains its token only
 * once the person allows that agent.
 */
describe('signing in through a linked sign-in provider', () => {
	let setup: Setup;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url);
	});

	beforeEach(() => {
		resetKeyringForTests(TEST_KEYRING);
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	it('asks the provider for the service’s scopes beside the sign-in’s own, and never forces the consent screen', async () => {
		const linked = await linkedProject();
		const { authorizeUrl } = await signInThrough(linked, upstreamPerson());

		const asked = scopesAsked(authorizeUrl);
		for (const scope of ['openid', 'email', 'profile', ...SERVICE_SCOPES]) {
			expect(asked).toContain(scope);
		}
		expect(authorizeUrl.searchParams.get('prompt')).toBeNull();
	});

	it('asks Google for offline access and remembered grants, and Microsoft for offline access, without a consent prompt', () => {
		const google = keepRequest(catalogueService('google', ['drive.readonly']));
		const microsoft = keepRequest(catalogueService('microsoft', ['Mail.Read']));

		expect(google.params).toEqual({
			access_type: 'offline',
			include_granted_scopes: 'true'
		});
		expect(google.scopes).toContain('drive.readonly');
		expect(microsoft.scopes).toContain('offline_access');
		expect(microsoft.scopes).toContain('Mail.Read');
		expect(microsoft.params).not.toHaveProperty('prompt');
	});

	it('connects the account the person signed in with, with the granted scopes, marked as connected at sign-in', async () => {
		const linked = await linkedProject();
		const claims = upstreamPerson();
		const { accountId } = await signInThrough(linked, claims);

		const [account] = await keptAccounts(present(accountId, 'the person'));
		expect(account).toMatchObject({
			serviceId: linked.service.id,
			upstreamId: claims.sub,
			label: claims.email,
			accessToken: 'kept-access-token',
			refreshToken: 'kept-refresh-token',
			via: 'sign_in'
		});
		for (const scope of SERVICE_SCOPES) {
			expect(present(account, 'the account').scopes).toContain(scope);
		}
	});

	it('refreshes the same account on the next sign-in and keeps its refresh token when the provider sends none', async () => {
		const linked = await linkedProject();
		const claims = upstreamPerson();
		const { accountId } = await signInThrough(linked, claims);
		await signInThrough(linked, claims, {
			access_token: 'second-access-token',
			refresh_token: undefined,
			expires_in: 3600
		});

		const accounts = await keptAccounts(present(accountId, 'the person'));
		expect(accounts).toHaveLength(1);
		expect(accounts[0]).toMatchObject({
			accessToken: 'second-access-token',
			refreshToken: 'kept-refresh-token'
		});
	});

	it('makes an account that needed reconnection usable again', async () => {
		const linked = await linkedProject();
		const claims = upstreamPerson();
		const { accountId } = await signInThrough(linked, claims);
		const [account] = await keptAccounts(present(accountId, 'the person'));
		await getConnectedAccountStore().put({
			...present(account, 'the account'),
			broken: { reason: 'refresh_rejected', at: epochTime(), notified: true }
		});

		await signInThrough(linked, claims);

		const [again] = await keptAccounts(present(accountId, 'the person'));
		expect(present(again, 'the account').broken).toBeUndefined();
	});

	it('lets an agent obtain the kept token only after the person allows it', async () => {
		const linked = await linkedProject();
		const { accountId } = await signInThrough(linked, upstreamPerson());
		const person = present(accountId, 'the person');
		const signedIn = await agentFor(setup, person);

		const before = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: linked.service.id
			})
		);
		const [account] = await keptAccounts(person);
		await allowAccount(signedIn.grantId, present(account, 'the account'));
		const after = granted(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: linked.service.id
			})
		);

		expect(before.reason).toBe('consent_required');
		expect(after.access_token).toBe('kept-access-token');
	});

	it('answers an agent with a reconnect link once a kept token without a refresh token has expired', async () => {
		const linked = await linkedProject();
		const { accountId } = await signInThrough(linked, upstreamPerson(), {
			access_token: 'short-lived-token',
			refresh_token: undefined,
			expires_in: 3600
		});
		const person = present(accountId, 'the person');
		const signedIn = await agentFor(setup, person);
		const [account] = await keptAccounts(person);
		const kept = present(account, 'the account');
		await allowAccount(signedIn.grantId, kept);
		await getConnectedAccountStore().put({
			...kept,
			accessTokenExpiresAt: epochTime() - 60
		});

		const body = refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: linked.service.id
			})
		);

		expect(body.reason).toBe('reconnect_required');
		const [after] = await keptAccounts(person);
		expect(present(after, 'the account').broken?.reason).toBe(
			'no_refresh_token'
		);
	});

	it('keeps nothing and asks for nothing more through a provider that is not linked', async () => {
		const linked = await linkedProject({ linked: false });
		const { authorizeUrl, accountId } = await signInThrough(
			linked,
			upstreamPerson()
		);

		expect(scopesAsked(authorizeUrl)).toEqual(['openid', 'email', 'profile']);
		expect(await keptAccounts(present(accountId, 'the person'))).toEqual([]);
	});

	it('sends the person no mail when it keeps their account', async () => {
		const linked = await linkedProject();
		const claims = upstreamPerson();
		await signInThrough(linked, claims);

		expect(emailsTo(String(claims.email))).toEqual([]);
	});

	it('announces the account as connected at sign-in, then as updated, without a token', async () => {
		const linked = await linkedProject();
		const claims = upstreamPerson();
		const seen: unknown[] = [];
		const listen = (event: unknown) => seen.push(event);
		eventBus.on('connected_account.connected', listen);
		eventBus.on('connected_account.updated', listen);
		try {
			await signInThrough(linked, claims);
			await signInThrough(linked, claims);
		} finally {
			eventBus.off('connected_account.connected', listen);
			eventBus.off('connected_account.updated', listen);
		}

		expect(seen).toHaveLength(2);
		expect(seen).toEqual([
			expect.objectContaining({ via: 'sign_in' }),
			expect.objectContaining({ via: 'sign_in' })
		]);
		expect(JSON.stringify(seen)).not.toContain('kept-');
	});
});
