import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.js';
import { ProvisioningConnectionStore } from 'lib/adapters/memory/index.js';
import type { NewProvisioningConnection } from 'lib/adapters/types.js';

/*
 * The store's half of overlapping credentials and the cross-bucket holds read (specs/088), against the in-memory
 * adapter the suite runs on. database/verify_088_scim_overlap.ts runs the same contract on MongoDB and
 * PostgreSQL, which is what proves each write is one conditional statement there.
 */

const at = (minute: number) => new Date(Date.UTC(2026, 9, 12, 12, minute));
const DIGEST_A = 'a'.repeat(64);
const DIGEST_B = 'b'.repeat(64);

let seq = 0;
function connection(
	overrides: Partial<NewProvisioningConnection> = {}
): NewProvisioningConnection {
	seq += 1;
	return {
		_id: `conn-${seq}`,
		bucketId: 'bucket-a',
		displayName: `Directory ${seq}`,
		enabled: true,
		providerId: `corp-${seq}`,
		correlation: { claim: 'preferred_username', attribute: 'userName' },
		emailTrust: 'untrusted',
		oauthCredential: { kind: 'secret', digest: DIGEST_B, issuedAt: at(0) },
		...overrides
	};
}

/**
 * @proves A previous credential is found by its digest, ended once however many administrators end it
 * together, and its use recorded without touching the current value's; the current value's first use is
 * written once; and the holds read lists every held connection and no other.
 */
describe('the provisioning connection store, for overlapping credentials', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	it('finds a connection by its previous static token’s digest', async () => {
		const store = new ProvisioningConnectionStore();
		const created = await store.create(
			connection({
				staticTokenDigest: DIGEST_B,
				previousStaticToken: {
					digest: DIGEST_A,
					issuedAt: at(0),
					replacedAt: at(1)
				}
			})
		);

		expect((await store.findByPreviousStaticTokenDigest(DIGEST_A))?._id).toBe(
			created._id
		);
		expect(await store.findByStaticTokenDigest(DIGEST_A)).toBeNull();
	});

	it('removes a previous value once when two administrators end it together', async () => {
		const store = new ProvisioningConnectionStore();
		const created = await store.create(
			connection({
				previousSecret: { digest: DIGEST_A, issuedAt: at(0), replacedAt: at(1) }
			})
		);

		const outcomes = await Promise.all([
			store.retirePrevious(created._id, 'secret', DIGEST_A),
			store.retirePrevious(created._id, 'secret', DIGEST_A)
		]);

		expect(outcomes.filter(Boolean)).toHaveLength(1);
		expect((await store.find(created._id))?.previousSecret).toBeUndefined();
	});

	it('leaves a previous value that was replaced since the end was asked for', async () => {
		const store = new ProvisioningConnectionStore();
		const created = await store.create(
			connection({
				previousSecret: { digest: DIGEST_B, issuedAt: at(0), replacedAt: at(1) }
			})
		);

		expect(await store.retirePrevious(created._id, 'secret', DIGEST_A)).toBe(
			false
		);
		expect((await store.find(created._id))?.previousSecret?.digest).toBe(
			DIGEST_B
		);
	});

	it('writes the current secret’s first use once and never moves it', async () => {
		const store = new ProvisioningConnectionStore();
		const created = await store.create(connection());

		await store.noteCredentialUse(created._id, 'secret', 'current', at(5));
		await store.noteCredentialUse(created._id, 'secret', 'current', at(9));

		const stored = await store.find(created._id);
		expect(
			stored?.oauthCredential?.kind === 'secret' &&
				stored.oauthCredential.firstUsedAt
		).toEqual(at(5));
	});

	it('writes the current static token’s first use once', async () => {
		const store = new ProvisioningConnectionStore();
		const created = await store.create(
			connection({ staticTokenDigest: DIGEST_A, staticTokenIssuedAt: at(0) })
		);

		await store.noteCredentialUse(
			created._id,
			'static_token',
			'current',
			at(2)
		);
		await store.noteCredentialUse(
			created._id,
			'static_token',
			'current',
			at(3)
		);

		expect((await store.find(created._id))?.staticTokenFirstUsedAt).toEqual(
			at(2)
		);
	});

	it('records a previous value’s last use without touching the current value', async () => {
		const store = new ProvisioningConnectionStore();
		const created = await store.create(
			connection({
				previousSecret: { digest: DIGEST_A, issuedAt: at(0), replacedAt: at(1) }
			})
		);

		await store.noteCredentialUse(created._id, 'secret', 'previous', at(7));
		await store.noteCredentialUse(created._id, 'secret', 'previous', at(8));

		const stored = await store.find(created._id);
		expect(stored?.previousSecret?.lastUsedAt).toEqual(at(8));
		expect(
			stored?.oauthCredential?.kind === 'secret' &&
				stored.oauthCredential.firstUsedAt
		).toBeUndefined();
	});

	it('lists every held connection and none that is not held', async () => {
		const store = new ProvisioningConnectionStore();
		const held = await store.create(connection());
		const free = await store.create(connection());
		await store.holdIfFree(held._id, { since: at(3), count: 5 });

		const listed = await store.listHeld();

		expect(listed.map((c) => c._id)).toEqual([held._id]);
		expect(listed[0]).toMatchObject({
			bucketId: 'bucket-a',
			displayName: held.displayName,
			hold: { since: at(3), count: 5 }
		});
		expect(listed.map((c) => c._id)).not.toContain(free._id);
	});
});
