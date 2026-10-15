import type { UserBucket } from '../adapters/types.js';
import { now } from '../activity/clock.js';
import { monthOf } from '../activity/periods.js';
import { readPeriod } from '../activity/read.js';
import { catalogue, planOf, plansEnabled } from './catalogue.js';

/*
 * The monthly-active-user cap (specs/102): at or over it, a bucket stops accepting new self-service accounts —
 * self-registration, and a federated first sign-in that would create one. It never refuses a sign-in.
 *
 * The figure is the one already recorded per bucket for the current month, re-read at most every five minutes per
 * bucket per process. The cache is keyed by the plan and its cap as well as the month, so a plan change, a new
 * cap or a new month is seen at the next check without anything having to invalidate it. Another process may admit
 * sign-ups for up to five minutes after the cap is crossed: the cap is soft by decision.
 *
 * Fails open. A figure that cannot be read leaves sign-ups open — an internal fault must not lock new people out —
 * and is logged rather than recorded as a fault: the error store's capture sites are fixed, and this one would
 * report a datastore failure the activity reads already surface.
 */
const REREAD_MS = 5 * 60 * 1000;

interface Reading {
	readonly key: string;
	readonly paused: boolean;
	readonly at: number;
}

const readings = new Map<string, Reading>();

export async function signUpsPaused(
	bucket: Pick<UserBucket, '_id' | 'ownerGroupId' | 'planId'>
): Promise<boolean> {
	if (!plansEnabled()) return false;
	const plan = planOf(bucket, await catalogue());
	const cap = plan?.limits.monthlyActiveUsers ?? null;
	if (plan === null || cap === null) return false;

	const at = now();
	const month = monthOf(at);
	const key = `${plan.id}:${String(cap)}:${month}`;
	const known = readings.get(bucket._id);
	if (known && known.key === key && at.getTime() - known.at < REREAD_MS) {
		return known.paused;
	}

	let total: number;
	try {
		total = (await readPeriod(bucket._id, month, at))?.total ?? 0;
	} catch (error) {
		console.error('monthly active users unreadable; sign-ups left open', {
			bucketId: bucket._id,
			error
		});
		return false;
	}
	const paused = total >= cap;
	readings.set(bucket._id, { key, paused, at: at.getTime() });
	return paused;
}

/* For a spec that changes the recorded figure within one five-minute window. */
export function forgetSignUpReadings(): void {
	readings.clear();
}
