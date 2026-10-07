import { describe, it, expect, beforeAll } from 'bun:test';

import bootstrap from '../test_helper.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { encodeBase32, decodeBase32 } from 'lib/totp/base32.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import { ACCOUNT_FAILURE_CAP } from 'lib/totp/consts.ts';
import { verifyForAccount } from 'lib/totp/verify.ts';
import epochTime from 'lib/helpers/epoch_time.ts';

/*
 * The per-account failure window holds under concurrency, not only in sequence. It is the throttle
 * that survives starting a new interaction, so it is the one that has to hold, and each wrong code read
 * the failure count and wrote back that count plus one: a burst of parallel guesses together advanced
 * it by one, and a six-digit code behind a known password was guessable at the rate the per-origin
 * limiter allowed rather than ten per window.
 *
 * Proved at the verification function because the door in front of it adds a second, per-interaction
 * cap that a burst inside one interaction would hit first, which is not the property in question.
 */

const SECRET = encodeBase32(Buffer.from('12345678901234567890', 'ascii'));
const BUCKET = 'concurrent-totp-bucket';

/**
 * @proves An account's second factor accepts no more wrong codes per window than its cap however many
 * arrive at once, so a burst of wrong ones leaves even the right code refused.
 */
describe('a second factor guessed concurrently', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'totp' });
	});

	it('refuses the right code after a burst of wrong ones', async () => {
		const store = getUserStore(BUCKET);
		const user = await store.create(
			`burst-${Math.random()}@x.io`,
			'hash',
			true
		);
		await store.update(user._id, {
			totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0 }
		});
		const right = hotp(decodeBase32(SECRET), stepFor(epochTime()));
		const wrong = right === '000000' ? '111111' : '000000';

		await Promise.all(
			Array.from({ length: ACCOUNT_FAILURE_CAP * 3 }, () =>
				verifyForAccount(BUCKET, user._id, wrong)
			)
		);
		const outcome = await verifyForAccount(BUCKET, user._id, right);

		expect(outcome).toEqual({ ok: false, reason: 'throttled' });
	});
});
