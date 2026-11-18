import { checkedAdapter } from '../adapters/index.js';
import epochTime from '../helpers/epoch_time.js';
import { SignInAlertClaimPayload } from './types.js';

/* At most this many emails about new sign-ins reach one account in a UTC day (FR-012). */
export const DAILY_ALERTS = 5;

/* A claim outlives its day by a day, so a clock a little off never frees one early. */
const CLAIM_SECONDS = 2 * 86_400;

function claims() {
	return checkedAdapter('SignInAlertClaim', SignInAlertClaimPayload);
}

/*
 * Takes the right to email an account about a sign-in (specs/138 research R5): first the account's network and
 * browser for the day, then one of the account's daily slots. Each is an insert-if-absent, so of two processes
 * flushing the same sign-ins exactly one is told yes; a taken pair keeps a second email about the same place away,
 * five taken slots keep a sixth. A pair won and no slot left stays taken: the day's emails are spent either way.
 */
export async function claim(
	bucketId: string,
	accountId: string,
	day: string,
	network: string,
	browser: string
): Promise<boolean> {
	const payload = { accountId, exp: epochTime() + CLAIM_SECONDS };
	const base = `${bucketId}:${accountId}:${day}`;
	if (
		!(await claims().create(
			`${base}:${network}:${browser}`,
			payload,
			CLAIM_SECONDS
		))
	) {
		return false;
	}
	for (let slot = 0; slot < DAILY_ALERTS; slot += 1) {
		if (
			await claims().create(
				`${base}:slot:${String(slot)}`,
				payload,
				CLAIM_SECONDS
			)
		) {
			return true;
		}
	}
	return false;
}
