import { describe, it, expect, beforeAll, spyOn } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { encodeBase32, decodeBase32 } from 'lib/totp/base32.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import { verifyForAccount } from 'lib/totp/verify.ts';
import epochTime from 'lib/helpers/epoch_time.ts';

/*
 * One code, one sign-in, under concurrency as well as in sequence; and a factor that was cleared while its code was
 * being checked stays cleared. Both were open while the replay guard was a `lastStep` read from the person, checked,
 * and written back as a whole `totp` object: racing verifications all passed before either wrote, and the write could
 * put back a factor an administrator had just removed.
 *
 * Proved at the verification function, as the burst in concurrent_guesses.spec.ts is: the door in front of it adds a
 * per-interaction counter that is not the property in question.
 */

const SECRET = encodeBase32(Buffer.from('12345678901234567890', 'ascii'));
const BUCKET = 'totp-replay-bucket';

async function enrolledAccount() {
	const store = getUserStore(BUCKET);
	const user = await store.create(`replay-${Math.random()}@x.io`, 'hash', true);
	await store.update(user._id, {
		totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0 }
	});
	return user._id;
}

const currentCode = () => hotp(decodeBase32(SECRET), stepFor(epochTime()));

/**
 * @proves A code from an authenticator app signs in once however many requests carry it at the same moment, and a
 * second factor cleared while its code is being checked neither signs the person in nor comes back.
 */
describe('a second-factor code used more than once', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'totp' });
	});

	it('lets exactly one of several simultaneous uses of the same code through', async () => {
		const accountId = await enrolledAccount();
		const code = currentCode();

		const outcomes = await Promise.all(
			Array.from({ length: 6 }, () => verifyForAccount(BUCKET, accountId, code))
		);

		expect(outcomes.filter((outcome) => outcome.ok)).toHaveLength(1);
		expect(
			outcomes.filter((outcome) => !outcome.ok && outcome.reason === 'invalid')
		).toHaveLength(5);
	});

	it('refuses the same code once it has signed someone in', async () => {
		const accountId = await enrolledAccount();
		const code = currentCode();

		expect(await verifyForAccount(BUCKET, accountId, code)).toEqual({
			ok: true
		});
		expect(await verifyForAccount(BUCKET, accountId, code)).toEqual({
			ok: false,
			reason: 'invalid'
		});
	});

	it('leaves a factor cleared during the check cleared, and does not sign in on it', async () => {
		const accountId = await enrolledAccount();
		const store = getUserStore(BUCKET);
		const read = store.find.bind(store);
		const find = spyOn(store, 'find').mockImplementationOnce(async (id) => {
			const before = await read(id);
			// An administrator resets the authenticator after the check has read it.
			await store.update(id, { totp: undefined });
			return before;
		});
		try {
			const outcome = await verifyForAccount(BUCKET, accountId, currentCode());
			expect(outcome).toEqual({ ok: false, reason: 'not_enrolled' });
		} finally {
			find.mockRestore();
		}

		expect((await store.find(accountId))?.totp).toBeUndefined();
	});
});
