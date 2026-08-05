import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { getUserStore, resetAdminMemoryStores } from 'lib/adapters/index.ts';
import { assertNoPendingInterceptors, mock } from '../fetch_mock.ts';
import { eventBus } from 'lib/event_bus.ts';
import { idpStub } from './idp_stub.ts';
import {
	CLIENT,
	expectRefusalPage,
	get,
	provider,
	seedBucket,
	signedInAccountIds,
	startInteraction,
	walk
} from './harness.ts';

/*
 * Every way a federated sign-in is refused.
 *
 * Two claims are made about each refusal, and only the pair is meaningful: it answers the right status with a
 * rendered page (a refusal that answers 200 tells a non-browser client the opposite of what it says to a
 * reader), and it leaves **nothing** behind. The second is asserted on the store rather than on the
 * response, because "no account was created" is not visible in a status code.
 */

/* Collects the reasons the flow emits, which is the only place a specific cause is allowed to appear. */
function captureReasons(event: string) {
	const seen: string[] = [];
	const listener = (payload: { reason?: string }) => {
		if (payload?.reason) seen.push(payload.reason);
	};
	eventBus.on(event, listener);
	return {
		seen,
		stop: () => eventBus.off(event, listener)
	};
}

describe('federated sign-in: the decision ladder refuses', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin' });
	});

	beforeEach(() => {
		resetAdminMemoryStores();
	});

	/*
	 * Interceptors are global and single-use, and several cases here deliberately never reach the key set —
	 * verification fails first. Dropping them between cases is what stops one case's unfetched interceptor
	 * failing the next; the caching case, where the fetch count *is* the assertion, keeps
	 * assertNoPendingInterceptors().
	 */
	afterEach(() => {
		mock.restore();
	});

	it('refuses to link an untrusted provider to an address an account already holds', async () => {
		const idp = await idpStub('https://idp-untrusted.test');
		// emailTrusted defaults false: the operator has not said this provider's addresses can be believed.
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(idp.origin)]
		});
		const store = getUserStore(bucketId);
		const existing = await store.create('taken@acme.test', 'hash', [], true);

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		const { callback } = await walk(uid, cookie, {
			idp,
			claims: { email: 'taken@acme.test', email_verified: true }
		});

		expectRefusalPage(callback, 403);
		// The one refusal with a usable next step.
		expect(callback.text).toContain('already exists');
		expect(callback.text).toContain('password');

		// Nothing taken over, nothing added, nobody signed in.
		expect((await store.list())[0]?.federated ?? []).toEqual([]);
		expect(signedInAccountIds()).not.toContain(existing._id);
	});

	it('refuses a trusted provider whose assertion does not mark the address verified', async () => {
		const idp = await idpStub('https://idp-unverified.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});
		const store = getUserStore(bucketId);
		await store.create('taken2@acme.test', 'hash', [], true);

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		// Both halves are required; the operator's trust alone is not enough.
		const { callback } = await walk(uid, cookie, {
			idp,
			claims: { email: 'taken2@acme.test', email_verified: false }
		});

		expectRefusalPage(callback, 403);
		expect((await store.list())[0]?.federated ?? []).toEqual([]);
	});

	it('treats a merely truthy email_verified as unverified', async () => {
		const idp = await idpStub('https://idp-truthy.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});
		const store = getUserStore(bucketId);
		await store.create('truthy@acme.test', 'hash', [], true);

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		// `=== true` exactly: a provider that stringifies its booleans must not clear this bar.
		const { callback } = await walk(uid, cookie, {
			idp,
			claims: { email: 'truthy@acme.test', email_verified: 'true' }
		});

		expectRefusalPage(callback, 403);
		expect((await store.list())[0]?.federated ?? []).toEqual([]);
	});

	it('refuses an assertion carrying no address at the configured claim', async () => {
		const idp = await idpStub('https://idp-noemail.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		const { callback } = await walk(uid, cookie, {
			idp,
			claims: { email_verified: true }
		});

		expectRefusalPage(callback, 400);
		expect(await getUserStore(bucketId).list()).toEqual([]);
	});

	it('reads the address from a provider-specific claim when one is configured', async () => {
		const idp = await idpStub('https://idp-upn.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.origin, { emailTrusted: true, emailClaim: 'upn' })
			]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		// Corporate providers commonly use `upn`; `email` is absent entirely here.
		const { complete } = await walk(uid, cookie, {
			idp,
			claims: { upn: 'corp@acme.test', email_verified: true }
		});

		expect(complete?.status).toBe(303);
		const created = (await getUserStore(bucketId).list())[0];
		expect(created?.email).toBe('corp@acme.test');
	});

	it('admits an allowed domain case-insensitively and refuses a lookalike suffix', async () => {
		const allowed = await idpStub('https://idp-domain-ok.test');
		const bucketA = await seedBucket(CLIENT, {
			federation: [
				provider(allowed.origin, {
					emailTrusted: true,
					allowedEmailDomains: ['acme.test']
				})
			]
		});

		allowed.expectDiscovery();
		const first = await startInteraction();
		const okWalk = await walk(first.uid, first.cookie, {
			idp: allowed,
			claims: { email: 'Alice@ACME.test', email_verified: true }
		});
		expect(okWalk.complete?.status).toBe(303);
		expect(await getUserStore(bucketA).list()).toHaveLength(1);
		const evil = await idpStub('https://idp-domain-evil.test');
		const bucketB = await seedBucket('fed-strict-app', {
			federation: [
				provider(evil.origin, {
					emailTrusted: true,
					allowedEmailDomains: ['acme.test']
				})
			]
		});

		evil.expectDiscovery();
		const second = await startInteraction('fed-strict-app');
		const evilWalk = await walk(second.uid, second.cookie, {
			idp: evil,
			// A suffix comparison would have admitted this. The domain part is compared whole.
			claims: { email: 'bob@acme.test.evil.test', email_verified: true }
		});

		expectRefusalPage(evilWalk.callback, 403);
		expect(await getUserStore(bucketB).list()).toEqual([]);
	});

	it('refuses to provision when the provider is configured for existing accounts only', async () => {
		const idp = await idpStub('https://idp-existingonly.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [
				provider(idp.origin, {
					emailTrusted: true,
					provisioning: 'existing_only'
				})
			]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		const { callback } = await walk(uid, cookie, {
			idp,
			claims: { email: 'stranger@acme.test', email_verified: true }
		});

		expectRefusalPage(callback, 403);
		expect(await getUserStore(bucketId).list()).toEqual([]);
	});

	it('refuses a deactivated account on the existing-link branch', async () => {
		const idp = await idpStub('https://idp-inactive-link.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(idp.origin)]
		});
		const store = getUserStore(bucketId);
		const account = await store.create('frozen@acme.test', 'hash', [], true);
		await store.update(account._id, {
			active: false,
			federated: [
				{
					providerId: 'acme-sso',
					sub: 'upstream-subject-1',
					linkedAt: new Date()
				}
			]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		const { callback } = await walk(uid, cookie, {
			idp,
			claims: { email: 'frozen@acme.test' }
		});

		// A live link does not outrank deactivation.
		expectRefusalPage(callback, 403);
		expect(signedInAccountIds()).not.toContain(account._id);
	});

	it('refuses a deactivated account on the fresh-link branch', async () => {
		const idp = await idpStub('https://idp-inactive-fresh.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});
		const store = getUserStore(bucketId);
		const account = await store.create('frozen2@acme.test', 'hash', [], true);
		await store.update(account._id, { active: false });

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		const { callback } = await walk(uid, cookie, {
			idp,
			claims: { email: 'frozen2@acme.test', email_verified: true }
		});

		expectRefusalPage(callback, 403);
		// Refused before any link is written, so a frozen account cannot be quietly annexed.
		expect((await store.list())[0]?.federated ?? []).toEqual([]);
	});

	it('keeps one identity bound to one account when another holds the same address', async () => {
		const idp = await idpStub('https://idp-unique.test');
		const bucketId = await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});
		const store = getUserStore(bucketId);
		const linked = await store.create('linked@acme.test', 'hash', [], true);
		await store.update(linked._id, {
			federated: [
				{
					providerId: 'acme-sso',
					sub: 'upstream-subject-1',
					linkedAt: new Date()
				}
			]
		});
		const other = await store.create('other@acme.test', 'hash', [], true);

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		// The assertion carries the *other* account's address, but the same subject.
		const { complete } = await walk(uid, cookie, {
			idp,
			claims: { email: 'other@acme.test', email_verified: true }
		});

		expect(complete?.status).toBe(303);
		/*
		 * The link wins, because the link *is* the identity — the address is only how one is established. So
		 * the second account never acquires this subject, and the identity stays one-to-one.
		 */
		expect(signedInAccountIds()).toContain(linked._id);
		expect(signedInAccountIds()).not.toContain(other._id);
		const reloaded = await store.find(other._id);
		expect(reloaded?.federated ?? []).toEqual([]);
	});
});

describe('federated sign-in: the round trip and the assertion are refused', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'signin' });
	});

	beforeEach(() => {
		resetAdminMemoryStores();
	});

	/*
	 * Interceptors are global and single-use, and several cases here deliberately never reach the key set —
	 * verification fails first. Dropping them between cases is what stops one case's unfetched interceptor
	 * failing the next; the caching case, where the fetch count *is* the assertion, keeps
	 * assertNoPendingInterceptors().
	 */
	afterEach(() => {
		mock.restore();
	});

	it('refuses an unknown, replayed or expired state with one answer', async () => {
		const idp = await idpStub('https://idp-state.test');
		await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		const { state, callback } = await walk(uid, cookie, {
			idp,
			claims: { email: 'state@acme.test', email_verified: true }
		});
		expect(callback.status).toBe(303);

		// Spent: a round trip is one attempt.
		const replay = await get(
			`/federation/callback?code=c&state=${encodeURIComponent(state)}`
		);
		expectRefusalPage(replay, 400);

		const unknown = await get('/federation/callback?code=c&state=never-minted');
		expectRefusalPage(unknown, 400);
		// Indistinguishable, so the holder of one dead value learns nothing about another.
		expect(unknown.text).toBe(replay.text);
	});

	it('refuses a handoff that is replayed or presented under another interaction', async () => {
		const idp = await idpStub('https://idp-handoff.test');
		await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		idp.expectDiscovery();
		const first = await startInteraction();
		const { callback } = await walk(first.uid, first.cookie, {
			idp,
			claims: { email: 'handoff@acme.test', email_verified: true }
		});
		const completePath = callback.location;
		const signedIn = signedInAccountIds().length;

		/*
		 * Replayed after a completed sign-in. The refusal comes from the interaction guard rather than from a
		 * federation page, because a finished authorization request no longer has an interaction to resume —
		 * which is a stronger refusal than the handoff check, not a weaker one. What matters is the property:
		 * spending it twice signs nobody in twice.
		 */
		const replay = await get(completePath, first.cookie);
		expect(replay.status).not.toBe(303);
		expect(signedInAccountIds()).toHaveLength(signedIn);
	});

	it('refuses a handoff belonging to a different interaction', async () => {
		const idp = await idpStub('https://idp-crossint.test');
		await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		idp.expectDiscovery();
		const victim = await startInteraction();
		const attacker = await startInteraction();
		const { callback } = await walk(victim.uid, victim.cookie, {
			idp,
			claims: { email: 'cross@acme.test', email_verified: true }
		});

		const ref = new URL(`http://e.ly${callback.location}`).searchParams.get(
			'ref'
		);
		// The same ref, spent inside an interaction it does not belong to.
		const stolen = await get(
			`/ui/${attacker.uid}/federation/complete?ref=${encodeURIComponent(ref ?? '')}`,
			attacker.cookie
		);

		expectRefusalPage(stolen, 400);
		// The attacker's interaction gains nothing; only the victim's own legitimate sign-in stands.
		expect(signedInAccountIds()).not.toContain(attacker.uid);
	});

	it('answers 502 when the provider cannot be reached for its metadata', async () => {
		const idp = await idpStub('https://idp-down.test');
		await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		idp.expectDiscoveryFailure(503);
		const { uid, cookie } = await startInteraction();
		const start = await get(`/ui/${uid}/federation/acme-sso/start`, cookie);

		// The other side is broken, and saying so distinguishes it from "you are not allowed".
		expectRefusalPage(start, 502);
	});

	it('answers 502 when the token endpoint refuses the exchange', async () => {
		const idp = await idpStub('https://idp-tokenfail.test');
		await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		const start = await get(`/ui/${uid}/federation/acme-sso/start`, cookie);
		const state = new URL(start.location).searchParams.get('state') ?? '';
		idp.expectTokenFailure(400, '{"error":"invalid_grant"}');

		const callback = await get(
			`/federation/callback?code=c&state=${encodeURIComponent(state)}`
		);
		expectRefusalPage(callback, 502);
	});

	/*
	 * The verification matrix. Every row answers 400 with the **same** body — which check failed is not
	 * something a caller gets to probe for by comparing responses — while the event bus receives a distinct
	 * reason, because an operator diagnosing a broken provider needs to know which one it was.
	 */
	const rejections: {
		name: string;
		reason: string;
		claims?: Record<string, unknown>;
		opts?: Record<string, unknown>;
	}[] = [
		{ name: 'a replayed nonce', reason: 'nonce', opts: { nonce: 'not-ours' } },
		{
			name: 'an audience that is not us',
			reason: 'audience',
			opts: { audience: 'someone-else' }
		},
		{
			name: 'an issuer that is not the configured one',
			reason: 'issuer',
			opts: { issuer: 'https://idp-elsewhere.test' }
		},
		{
			name: 'an expired assertion',
			reason: 'expired',
			opts: { expiresIn: -60 }
		},
		{ name: 'no subject', reason: 'subject', opts: { noSubject: true } },
		{
			name: 'a signature from a key the provider does not publish',
			reason: 'signature',
			opts: { foreignKey: true }
		},
		/*
		 * `alg: none` is refused as the algorithm violation it is, before jose is reached: it appears in
		 * neither the provider's advertised set nor this server's, so the header check rejects it.
		 */
		{
			name: 'an unsecured token',
			reason: 'algorithm',
			opts: { unsecured: true }
		}
	];

	for (const [index, row] of rejections.entries()) {
		it(`refuses ${row.name}, and says why only on the event bus`, async () => {
			const idp = await idpStub(`https://idp-reject-${index}.test`);
			const bucketId = await seedBucket(CLIENT, {
				federation: [provider(idp.origin, { emailTrusted: true })]
			});

			const reasons = captureReasons('federation.idtoken.error');
			try {
				idp.expectDiscovery();
				const { uid, cookie } = await startInteraction();
				const { callback } = await walk(uid, cookie, {
					idp,
					claims: {
						email: 'reject@acme.test',
						email_verified: true,
						...row.claims
					},
					opts: row.opts
				});

				expectRefusalPage(callback, 400);
				// Nothing about the cause reaches the page.
				expect(callback.text).not.toContain(row.reason);
				expect(reasons.seen).toEqual([row.reason]);
			} finally {
				reasons.stop();
			}

			// No refusal ever leaves an account behind.
			expect(await getUserStore(bucketId).list()).toEqual([]);
		});
	}

	it('refuses an algorithm the provider does not advertise', async () => {
		/*
		 * The provider advertises ES256 only, and signs with RS256. Driven from the metadata rather than by
		 * mis-signing, because a stub cannot sign RS256 bytes with an EC key — and this is the same violation
		 * from the side that a real misconfigured provider would show.
		 */
		const idp = await idpStub('https://idp-alg.test', {
			id_token_signing_alg_values_supported: ['ES256']
		});
		await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		const reasons = captureReasons('federation.idtoken.error');
		try {
			idp.expectDiscovery();
			const { uid, cookie } = await startInteraction();
			const { callback } = await walk(uid, cookie, {
				idp,
				claims: { email: 'alg@acme.test', email_verified: true }
			});

			expectRefusalPage(callback, 400);
			expect(reasons.seen).toEqual(['algorithm']);
		} finally {
			reasons.stop();
		}
	});

	it('returns to the login page with a notice when the user declines at the provider', async () => {
		const idp = await idpStub('https://idp-declined.test');
		await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction();
		const start = await get(`/ui/${uid}/federation/acme-sso/start`, cookie);
		const state = new URL(start.location).searchParams.get('state') ?? '';

		const callback = await get(
			`/federation/callback?error=access_denied&error_description=user+said+no&state=${encodeURIComponent(state)}`
		);

		/*
		 * A redirect, not a rendered login page: the client bundle derives the page and the interaction id
		 * from the pathname, so a login document served at the callback URL would hydrate into an empty root.
		 */
		expect(callback.status).toBe(303);
		expect(callback.location).toBe(
			`/ui/${uid}/login?notice=federation_aborted`
		);

		const page = await get(callback.location, cookie);
		expect(page.status).toBe(200);
		expect(page.text).toContain('was not completed');
		// The provider's own text never reaches the page: an identifier selects the message, it never supplies it.
		expect(page.text).not.toContain('user said no');
	});

	it('sends an unverified account to verification rather than signing it in', async () => {
		const idp = await idpStub('https://idp-verify.test');
		const bucketId = await seedBucket('fed-verify-app', {
			emailVerificationRequired: true,
			federation: [provider(idp.origin)]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteraction('fed-verify-app');
		const { complete } = await walk(uid, cookie, {
			idp,
			// Untrusted provider, so the provisioned account is not verified.
			claims: { email: 'unverified@acme.test' }
		});

		// The same notice a password registration lands on, reusing the same challenge.
		expect(complete?.status).toBe(303);
		expect(complete?.location).toBe(`/ui/${uid}/login?notice=verify`);

		const account = (await getUserStore(bucketId).list())[0];
		expect(account?.verified).toBe(false);
		// Provisioned, but not signed in: verification is a gate, not a formality.
		expect(signedInAccountIds()).not.toContain(account?._id);
	});

	it('reads the provider metadata once for two sign-ins', async () => {
		const idp = await idpStub('https://idp-cached.test');
		await seedBucket(CLIENT, {
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		// One interceptor, two sign-ins. The second proves the cache by not needing another — and an unhit
		// interceptor would fail this case, so the count is pinned in both directions.
		idp.expectDiscovery();

		const first = await startInteraction();
		const a = await walk(first.uid, first.cookie, {
			idp,
			claims: { email: 'cache1@acme.test', email_verified: true }
		});
		expect(a.complete?.status).toBe(303);

		const second = await startInteraction();
		const b = await walk(second.uid, second.cookie, {
			idp,
			claims: { email: 'cache2@acme.test', email_verified: true }
		});
		expect(b.complete?.status).toBe(303);

		// Two sign-ins, one metadata interceptor and one key-set interceptor, both hit exactly once.
		assertNoPendingInterceptors();
	});
});
