/*
 * How long a deleted bucket is held before it is destroyed (specs/090).
 *
 * Fixed and not a setting, by the owner's decision: a period an operator can shorten is a period an
 * operator under pressure shortens to nothing, and then a mistaken deletion is as final as it was before
 * this existed. Thirty days is long enough to notice a wrong bucket, and Delete now is the way to end it
 * early on purpose.
 *
 * Deliberately imports nothing, so the console, the stores and the routes can all read it.
 */
export const BUCKET_DELETION_HOLD_DAYS = 30;

/*
 * How long one destruction holds a bucket before another may start on it. Long enough for the slowest
 * destruction of a large bucket; short enough that a crashed one is finished by the next hourly pass.
 */
export const BUCKET_PURGE_CLAIM_MS = 15 * 60 * 1000;

const DAY_MS = 24 * 60 * 60 * 1000;

export function purgeAtOf(scheduledAt: Date): Date {
	return new Date(scheduledAt.getTime() + BUCKET_DELETION_HOLD_DAYS * DAY_MS);
}

/* Present means scheduled; absent means active. The field's only meaning, read here and nowhere else. */
export function isScheduledForDeletion(bucket: {
	deletion?: unknown;
}): boolean {
	return bucket.deletion !== undefined && bucket.deletion !== null;
}
