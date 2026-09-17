import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import { jwtVerify } from 'jose';
import { setSystemTime } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { getUserStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { mock } from '../fetch_mock.ts';
import { appleStub, githubStub, microsoftStub } from './recognised_stubs.ts';
import {
	CLIENT,
	get,
	provider,
	seedBucket,
	signedInAccountIds,
	startInteraction,
	walk
} from './harness.ts';

/*
 * Signing in through the three recognised providers that are not Google, each of which breaks a different
 * assumption the Google work left standing.
 *
 * These providers have real, fixed origins, so they cannot follow the one-origin-per-case rule the Google
 * suites follow. ./recognised_stubs.ts satisfies it the other two available ways — clearing the metadata
 * cache per stub, and advertising the key set at a per-case URL. Nothing here should need to think about it.
 */

/**
 * @proves An end user signs in through Microsoft, Apple or GitHub; a Microsoft identity from an
 * organisation the connection does not permit is refused; a GitHub account is identified by its
 * primary verified address even when its profile hides one and refused outright when it has none;
 * and an Apple connection keeps working past the point where a credential fixed at connection time
 * would have expired.
 */
describe('signing in through a recognised provider', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin' });
	});

	beforeEach(() => {
		resetAdminMemoryStores();
		mock.restore();
	});

	/* ------------------------------------------------------------- Microsoft */

	it('signs in a person from the organisation the connection permits', async () => {
		const idp = await microsoftStub('acme-tenant-id');
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'microsoft',
					clientId: idp.clientId,
					tenant: idp.tenant,
					emailTrusted: true
				})
			]
		});
		idp.expectDiscovery();

		const { uid, cookie } = await startInteraction();
		const { complete } = await walk(uid, cookie, undefined, {
			providerId: 'microsoft',
			onAuthorize: (url) =>
				idp.answerToken(url, {
					email: 'someone@acme.test',
					email_verified: true
				})
		});

		expect(complete?.status).toBe(303);
		const users = await getUserStore(bucketId).list();
		expect(users.map((user) => user.email)).toEqual(['someone@acme.test']);
		// Named rather than counted: sessions are process state and outlive a case, so a count here would
		// measure what ran before it.
		expect(signedInAccountIds()).toContain(users[0]!._id);
	});

	it('refuses a person whose organisation the connection does not permit, naming neither them nor it', async () => {
		const idp = await microsoftStub('acme-tenant-id');
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'microsoft',
					clientId: idp.clientId,
					tenant: idp.tenant,
					emailTrusted: true
				})
			]
		});
		idp.expectDiscovery();

		const { uid, cookie } = await startInteraction();
		const { callback } = await walk(uid, cookie, undefined, {
			providerId: 'microsoft',
			onAuthorize: (url) =>
				idp.answerToken(
					url,
					{ email: 'outsider@other.test', email_verified: true },
					// A perfectly valid assertion — from somewhere else.
					{ assertingTenant: 'some-other-tenant-id' }
				)
		});

		expect(callback.status).toBeGreaterThanOrEqual(400);
		// No account exists in this bucket at all, so none was signed in: a stronger claim than a session
		// count, which is process state shared with every other case in the file.
		expect(await getUserStore(bucketId).list()).toHaveLength(0);
		// The page may not disclose who arrived, or from where: this route is unauthenticated.
		expect(callback.text).not.toContain('outsider@other.test');
		expect(callback.text).not.toContain('some-other-tenant-id');
	});

	it('admits any organisation when the administrator chose to', async () => {
		const idp = await microsoftStub('common');
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'microsoft',
					clientId: idp.clientId,
					tenant: 'common',
					emailTrusted: true
				})
			]
		});
		// The document for this endpoint names the issuer as a literal placeholder, which is the shape an
		// equality check can never satisfy.
		idp.expectTemplatedDiscovery();

		const { uid, cookie } = await startInteraction();
		const { complete } = await walk(uid, cookie, undefined, {
			providerId: 'microsoft',
			onAuthorize: (url) =>
				idp.answerToken(
					url,
					{ email: 'anyone@elsewhere.test', email_verified: true },
					{ assertingTenant: 'a-completely-different-tenant' }
				)
		});

		expect(complete?.status).toBe(303);
		expect(await getUserStore(bucketId).list()).toHaveLength(1);
	});

	it('identifies a person by the address the provider does supply when the usual claim is empty', async () => {
		const idp = await microsoftStub('acme-tenant-id');
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'microsoft',
					clientId: idp.clientId,
					tenant: idp.tenant,
					emailTrusted: true
				})
			]
		});
		idp.expectDiscovery();

		const { uid, cookie } = await startInteraction();
		await walk(uid, cookie, undefined, {
			providerId: 'microsoft',
			onAuthorize: (url) =>
				idp.answerToken(url, {
					// No `email` at all, which is what an account without a mailbox gets.
					preferred_username: 'staffer@acme.test',
					email_verified: true
				})
		});

		const users = await getUserStore(bucketId).list();
		expect(users.map((user) => user.email)).toEqual(['staffer@acme.test']);
	});

	it('refuses a person for want of an address when the fallback holds something that is not one', async () => {
		const idp = await microsoftStub('acme-tenant-id');
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'microsoft',
					clientId: idp.clientId,
					tenant: idp.tenant,
					emailTrusted: true
				})
			]
		});
		idp.expectDiscovery();

		const { uid, cookie } = await startInteraction();
		const { callback } = await walk(uid, cookie, undefined, {
			providerId: 'microsoft',
			onAuthorize: (url) =>
				idp.answerToken(url, {
					// Microsoft documents this field as possibly a phone number or a bare username. Treating
					// one as an address would provision an account nothing can reach.
					preferred_username: '+15550100',
					email_verified: true
				})
		});

		expect(callback.status).toBeGreaterThanOrEqual(400);
		expect(await getUserStore(bucketId).list()).toHaveLength(0);
	});

	/* ----------------------------------------------------------------- Apple */

	it('signs in a person through Apple, presenting a credential Apple can verify', async () => {
		const idp = await appleStub();
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'apple',
					clientId: idp.clientId,
					clientSecret: undefined,
					teamId: idp.teamId,
					keyId: idp.keyId,
					signingKey: idp.signingKey,
					scopes: ['openid', 'email', 'name'],
					emailTrusted: true
				})
			]
		});
		idp.expectDiscovery();

		const { uid, cookie } = await startInteraction();
		const { authorizeUrl, complete } = await walk(uid, cookie, undefined, {
			providerId: 'apple',
			returnBy: 'POST',
			onAuthorize: (url) =>
				idp.answerToken(url, {
					email: 'someone@privaterelay.appleid.com',
					email_verified: true,
					is_private_email: true
				})
		});

		// Requested the way Apple requires when a name or an address is asked for; it refuses otherwise.
		expect(authorizeUrl.searchParams.get('response_mode')).toBe('form_post');
		expect(complete?.status).toBe(303);

		// A relay address is still an address Apple verified and routes, so it is treated as the person's.
		const users = await getUserStore(bucketId).list();
		expect(users.map((user) => user.email)).toEqual([
			'someone@privaterelay.appleid.com'
		]);

		const presented = idp.presentedCredential();
		expect(presented).toBeDefined();
		const verified = await jwtVerify(presented!, idp.verificationKey, {
			issuer: idp.teamId,
			subject: idp.clientId,
			audience: idp.issuer
		});
		expect(verified.protectedHeader.kid).toBe(idp.keyId);
	});

	it('signs in a person through Apple long after a credential fixed at connection time would have expired', async () => {
		const idp = await appleStub();
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'apple',
					clientId: idp.clientId,
					clientSecret: undefined,
					teamId: idp.teamId,
					keyId: idp.keyId,
					signingKey: idp.signingKey,
					scopes: ['openid', 'email', 'name'],
					emailTrusted: true
				})
			]
		});

		/*
		 * Well past Apple's six-month ceiling. Anything minted when this connection was saved is now
		 * refused by Apple, and the stub refuses it too — it verifies what it is sent rather than accepting
		 * any string, so a passing result here means the credential was produced now.
		 */
		setSystemTime(new Date(Date.now() + 400 * 24 * 60 * 60 * 1000));
		try {
			idp.expectDiscovery();
			const { uid, cookie } = await startInteraction();
			const { complete } = await walk(uid, cookie, undefined, {
				providerId: 'apple',
				returnBy: 'POST',
				onAuthorize: (url) =>
					idp.answerToken(url, {
						email: 'later@acme.test',
						email_verified: true
					})
			});

			expect(complete?.status).toBe(303);
			const users = await getUserStore(bucketId).list();
			expect(signedInAccountIds()).toContain(users[0]!._id);
		} finally {
			setSystemTime();
		}
	});

	/* ---------------------------------------------------------------- GitHub */

	it('signs in a person through GitHub, which asserts no identity of its own', async () => {
		const idp = githubStub();
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'github',
					clientId: idp.clientId,
					scopes: ['read:user', 'user:email'],
					emailTrusted: true
				})
			]
		});
		idp.expectToken();
		idp.expectProfile({
			id: 4242,
			login: 'someone',
			name: 'Some One',
			email: 'someone@acme.test'
		});

		const { uid, cookie } = await startInteraction();
		const { authorizeUrl, complete } = await walk(uid, cookie, undefined, {
			providerId: 'github'
		});

		// No metadata document exists, so the endpoint came from the catalogue rather than from discovery.
		expect(authorizeUrl.origin).toBe('https://github.com');
		expect(complete?.status).toBe(303);

		const users = await getUserStore(bucketId).list();
		expect(users.map((user) => user.email)).toEqual(['someone@acme.test']);
	});

	it('signs in a person whose GitHub profile hides their address, by their primary verified one', async () => {
		const idp = githubStub();
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'github',
					clientId: idp.clientId,
					scopes: ['read:user', 'user:email'],
					emailTrusted: true
				})
			]
		});
		idp.expectToken();
		idp.expectProfile({ id: 909, login: 'private-person', email: null });
		idp.expectAddresses([
			{ email: 'old@acme.test', primary: false, verified: true },
			{ email: 'primary@acme.test', primary: true, verified: true }
		]);

		const { uid, cookie } = await startInteraction();
		const { complete } = await walk(uid, cookie, undefined, {
			providerId: 'github'
		});

		expect(complete?.status).toBe(303);
		const users = await getUserStore(bucketId).list();
		expect(users.map((user) => user.email)).toEqual(['primary@acme.test']);
	});

	it('refuses a GitHub account whose addresses are all unverified, provisioning and linking nothing', async () => {
		const idp = githubStub();
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'github',
					clientId: idp.clientId,
					scopes: ['read:user', 'user:email'],
					emailTrusted: true
				})
			]
		});
		const store = getUserStore(bucketId);
		// An account already exists at that address. An unverified assertion must not reach it.
		const existing = await store.create(
			'claimed@acme.test',
			'irrelevant-hash',
			[],
			true
		);

		idp.expectToken();
		idp.expectProfile({ id: 707, login: 'unverified-person', email: null });
		idp.expectAddresses([
			{ email: 'claimed@acme.test', primary: true, verified: false }
		]);

		const { uid, cookie } = await startInteraction();
		const { callback } = await walk(uid, cookie, undefined, {
			providerId: 'github'
		});

		expect(callback.status).toBeGreaterThanOrEqual(400);
		// The account that already held that address was not signed into, and gained no upstream identity.
		expect(signedInAccountIds()).not.toContain(existing._id);
		const users = await store.list();
		expect(users).toHaveLength(1);
		expect(users[0]?.federated ?? []).toHaveLength(0);
	});

	it('reports a GitHub permission that was never granted as that, not as an account with no address', async () => {
		const idp = githubStub();
		await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'github',
					clientId: idp.clientId,
					// Configured without the scope the addresses read requires.
					scopes: ['read:user'],
					emailTrusted: true
				})
			]
		});
		const reasons: string[] = [];
		const { eventBus } = await import('lib/event_bus.ts');
		const listener = (payload: { reason: string }) =>
			reasons.push(payload.reason);
		eventBus.on('federation.idtoken.error', listener);

		idp.expectToken();
		idp.expectProfile({ id: 606, login: 'no-permission', email: null });
		idp.expectAddresses({ status: 403 });

		try {
			const { uid, cookie } = await startInteraction();
			const { callback } = await walk(uid, cookie, undefined, {
				providerId: 'github'
			});
			expect(callback.status).toBeGreaterThanOrEqual(400);
		} finally {
			eventBus.off('federation.idtoken.error', listener);
		}

		/*
		 * The distinction an administrator acts on: a permission to add, not an account to chase. The reason
		 * travels on the event bus rather than to the page, because this route is unauthenticated.
		 */
		expect(reasons).toContain('missing_email_permission');
	});

	it('identifies a GitHub person by an identifier their login name cannot change', async () => {
		const idp = githubStub();
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.issuer, {
					id: 'github',
					clientId: idp.clientId,
					scopes: ['read:user', 'user:email'],
					emailTrusted: true
				})
			]
		});
		idp.expectToken();
		idp.expectProfile({
			id: 5151,
			login: 'before-the-rename',
			email: 'stable@acme.test'
		});

		const { uid, cookie } = await startInteraction();
		await walk(uid, cookie, undefined, { providerId: 'github' });

		const users = await getUserStore(bucketId).list();
		const identity = (users[0]?.federated ?? [])[0];
		/*
		 * A login can be renamed and the freed name claimed by somebody else, so a login as subject means a
		 * renamed account becomes a stranger and a reused name inherits an existing account.
		 */
		expect(identity?.sub).toBe('5151');
		expect(identity?.sub).not.toBe('before-the-rename');
	});
});
