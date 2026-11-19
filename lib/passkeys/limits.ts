import { checkedAdapter } from '../adapters/index.js';
import { callerAddressOf } from '../helpers/caller_address.js';
import epochTime from '../helpers/epoch_time.js';
import { FAILURES_PER_CALLER_PER_HOUR } from './consts.js';
import { PasskeyAttemptTallyPayload } from './types.js';

const HOUR = 60 * 60;

function tallies() {
	return checkedAdapter('PasskeyAttemptTally', PasskeyAttemptTallyPayload);
}

/*
 * The tally of failed passkey sign-ins from this request's caller in the current UTC hour (specs/139 research R10),
 * keyed as the mail limit keys its own (lib/mail_limit/tally.ts). A request with no address — one the server
 * dispatched to itself — has none: counting such requests together would make every in-process caller share one.
 */
function hourOf(
	request: Request
): { key: string; ends: number; now: number } | undefined {
	const caller = callerAddressOf(request);
	if (caller.from === 'unattributed') return undefined;
	const now = epochTime();
	const hourStart = now - (now % HOUR);
	return {
		key: `${caller.address}:${String(hourStart)}`,
		ends: hourStart + HOUR,
		now
	};
}

export type PasskeyAdmission =
	| { readonly admitted: true }
	| { readonly admitted: false; readonly retryAfter: number };

/*
 * Whether the caller may try a passkey now: refused once its failures this hour reached the bound, before anything is
 * looked up, so a refused attempt learns nothing about any passkey. Only reads; a success never counts.
 */
export async function admitPasskeyAttempt(
	request: Request
): Promise<PasskeyAdmission> {
	const hour = hourOf(request);
	if (!hour) return { admitted: true };
	const tally = await tallies().find(hour.key);
	return tally &&
		tally.exp > hour.now &&
		tally.count >= FAILURES_PER_CALLER_PER_HOUR
		? { admitted: false, retryAfter: hour.ends - hour.now }
		: { admitted: true };
}

/* One failed passkey attempt from this request's caller, counted in one atomic write. */
export async function countPasskeyFailure(request: Request): Promise<void> {
	const hour = hourOf(request);
	if (!hour) return;
	// Kept an hour past its own: a record that vanished at the boundary could be re-created by a late write.
	const keep = hour.ends + HOUR - hour.now;
	await tallies().create(hour.key, { count: 0, exp: hour.now + keep }, keep);
	await tallies().increment(hour.key, 'count');
}
