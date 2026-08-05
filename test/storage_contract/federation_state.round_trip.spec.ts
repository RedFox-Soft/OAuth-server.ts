import { describe, it, beforeAll, expect } from 'bun:test';
import crypto from 'crypto';

import bootstrap from '../test_helper.js';
import { TestAdapter } from 'test/models.js';
import epochTime from 'lib/helpers/epoch_time.js';
import {
	consumeHandoff,
	consumePending,
	openHandoff,
	openPending
} from 'lib/federation/state.js';
import { FederationStatePayload } from 'lib/federation/types.js';
import {
	areaNamed,
	indexesFor,
	ownerFieldsOf
} from 'lib/consts/storage_inventory.js';

/*
 * The round-trip record is written straight through `adapter('FederationState')` with no model class, as
 * PasswordResetChallenge is — so the schema-driven helpers in ./round_trip.js (which read
 * `instance.model`) do not apply, and the adapter is inspected directly.
 *
 * Two properties here have no other verification anywhere in the suite: that neither live identifier is
 * recoverable from storage, and that expiry is refused on read rather than trusted to the store.
 */

const records = () => TestAdapter.for('FederationState');
const digest = (value: string) =>
	crypto.createHash('sha256').update(value).digest('hex');

describe('storage contract: FederationState', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('stores a pending round trip under the digest of its state, and nowhere else', async () => {
		const { state, nonce, codeVerifier } = await openPending({
			interactionUid: 'int-1',
			bucketId: 'redfox',
			providerId: 'acme-sso',
			withPkce: true
		});

		const stored = records().syncFind(digest(state)) as
			Record<string, unknown> | undefined;
		expect(stored).toBeDefined();
		expect(stored!.stage).toBe('pending');
		expect(stored!.interactionUid).toBe('int-1');
		expect(stored!.bucketId).toBe('redfox');
		expect(stored!.providerId).toBe('acme-sso');
		expect(stored!.nonce).toBe(nonce);
		expect(stored!.codeVerifier).toBe(codeVerifier);

		// The record is not findable by the live value — only by its digest.
		expect(records().syncFind(state)).toBeUndefined();

		/*
		 * The property this spec exists for: the value the browser carries appears in no field. A datastore
		 * dump must not hand over anything replayable, which is why the id is a digest rather than the
		 * state itself (the PasswordResetChallenge rule).
		 */
		const serialised = JSON.stringify(stored);
		expect(serialised).not.toContain(state);
	});

	it('omits the verifier entirely when the upstream advertises no PKCE', async () => {
		const { state, codeVerifier } = await openPending({
			interactionUid: 'int-2',
			bucketId: 'redfox',
			providerId: 'acme-sso',
			withPkce: false
		});

		expect(codeVerifier).toBeUndefined();
		const stored = records().syncFind(digest(state)) as Record<string, unknown>;
		// Absent, not present-and-empty: an empty verifier sent to a token endpoint is a failed exchange.
		expect(stored).not.toHaveProperty('codeVerifier');
	});

	it('consumes a pending record once, and refuses the second attempt', async () => {
		const { state } = await openPending({
			interactionUid: 'int-3',
			bucketId: 'redfox',
			providerId: 'acme-sso',
			withPkce: true
		});

		const first = await consumePending(state);
		expect(first?.interactionUid).toBe('int-3');

		// Destroyed on the first read, so a replay arriving mid-flight finds nothing to race.
		expect(records().syncFind(digest(state))).toBeUndefined();
		expect(await consumePending(state)).toBeNull();
	});

	it('refuses a pending record whose expiry has passed even though the store still holds it', async () => {
		const { state } = await openPending({
			interactionUid: 'int-4',
			bucketId: 'redfox',
			providerId: 'acme-sso',
			withPkce: true
		});

		/*
		 * Exactly the state MongoDB's lazy TTL monitor leaves behind: the record is past its expiry and
		 * still present. Aged with syncUpdate because TestAdapter.upsert asserts a written `exp` matches
		 * the TTL it was given, so an inconsistent record cannot be forged through the front door.
		 */
		records().syncUpdate(digest(state), { exp: epochTime() - 1 });

		expect(await consumePending(state)).toBeNull();
		// Still consumed, so an expired record cannot be retried into existence.
		expect(records().syncFind(digest(state))).toBeUndefined();
	});

	it('stores a handoff under the digest of its ref, naming only the interaction and the account', async () => {
		const ref = await openHandoff({
			interactionUid: 'int-5',
			accountId: 'account-5'
		});

		const stored = records().syncFind(digest(ref)) as Record<string, unknown>;
		expect(stored.stage).toBe('complete');
		expect(stored.interactionUid).toBe('int-5');
		expect(stored.accountId).toBe('account-5');
		// The exchange context is spent and must not survive into the handoff.
		expect(stored).not.toHaveProperty('nonce');
		expect(stored).not.toHaveProperty('codeVerifier');
		expect(stored).not.toHaveProperty('bucketId');

		// Same rule as `state`: the live ref is not recoverable from what is at rest.
		expect(JSON.stringify(stored)).not.toContain(ref);
		expect(records().syncFind(ref)).toBeUndefined();
	});

	it('refuses a handoff presented under a different interaction', async () => {
		const ref = await openHandoff({
			interactionUid: 'int-6',
			accountId: 'account-6'
		});

		// A leaked ref must not be spendable inside whatever interaction its holder has a cookie for.
		expect(await consumeHandoff(ref, 'int-other')).toBeNull();
	});

	it('consumes a handoff once', async () => {
		const ref = await openHandoff({
			interactionUid: 'int-7',
			accountId: 'account-7'
		});

		expect((await consumeHandoff(ref, 'int-7'))?.accountId).toBe('account-7');
		expect(await consumeHandoff(ref, 'int-7')).toBeNull();
	});

	it('refuses an expired handoff the store still holds', async () => {
		const ref = await openHandoff({
			interactionUid: 'int-8',
			accountId: 'account-8'
		});
		records().syncUpdate(digest(ref), { exp: epochTime() - 1 });

		expect(await consumeHandoff(ref, 'int-8')).toBeNull();
	});

	it('persists nothing the payload schema does not declare', async () => {
		const { state } = await openPending({
			interactionUid: 'int-9',
			bucketId: 'redfox',
			providerId: 'acme-sso',
			withPkce: true
		});
		const ref = await openHandoff({
			interactionUid: 'int-9',
			accountId: 'account-9'
		});

		const declared = Object.keys(FederationStatePayload.properties);
		for (const id of [digest(state), digest(ref)]) {
			const stored = records().syncFind(id) as Record<string, unknown>;
			for (const key of Object.keys(stored)) {
				expect(declared).toContain(key);
			}
		}
	});

	it('is declared as an account-owned, reaped area with an index the sweep can use', () => {
		const area = areaNamed('FederationState');

		expect(area.kind).toBe('model');
		// Both stages are short-lived; a round-trip record outliving its interaction is a spendable sign-in.
		expect(area.reaped).toBe('expiresAt');
		/*
		 * Account-owned rather than unowned — a departure from what task 18 anticipated, forced by the
		 * reverse ownership check: the handoff stage carries `accountId`, and an area whose payload holds an
		 * owner field the table does not declare is a record no cascade sweeps. See research.md D5.
		 */
		expect(ownerFieldsOf(area)).toEqual(['accountId']);
		expect(area.owners.reason).toBeUndefined();
		// Derived from the ownership declaration, so the cascade's sweep is a point read, not a scan.
		expect(indexesFor(area)).toContainEqual({
			key: { 'payload.accountId': 1 }
		});
	});
});
