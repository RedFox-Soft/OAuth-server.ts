const DAY_MS = 24 * 60 * 60 * 1000;

/* The UTC day of `at`, `YYYY-MM-DD`, as every day in the usage-reporting state is written. */
export function dayOf(at: Date): string {
	return at.toISOString().slice(0, 10);
}

/* Midnight UTC `days` days after the start of `at`'s UTC day. */
export function startOfDayAfter(at: Date, days: number): Date {
	const start = Date.UTC(
		at.getUTCFullYear(),
		at.getUTCMonth(),
		at.getUTCDate()
	);
	return new Date(start + days * DAY_MS);
}
