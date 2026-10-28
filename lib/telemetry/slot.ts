const MINUTES_PER_DAY = 24 * 60;

/*
 * The minute of the UTC day this instance reports at. Derived from the identifier so that every process
 * of one instance agrees on it without talking to the others, it never moves, and instances are spread
 * across the day instead of all arriving at midnight. The identifier is the input here, never the output.
 */
export function slotOf(instanceId: string): number {
	return (
		parseInt(instanceId.replaceAll('-', '').slice(0, 8), 16) % MINUTES_PER_DAY
	);
}

export function minuteOfDay(at: Date): number {
	return at.getUTCHours() * 60 + at.getUTCMinutes();
}

/* The next moment this instance would report, from `at`. */
export function nextSlotAfter(instanceId: string, at: Date): Date {
	const slot = slotOf(instanceId);
	const today = new Date(
		Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate())
	);
	const candidate = new Date(today.getTime() + slot * 60 * 1000);
	return candidate.getTime() > at.getTime()
		? candidate
		: new Date(candidate.getTime() + MINUTES_PER_DAY * 60 * 1000);
}
