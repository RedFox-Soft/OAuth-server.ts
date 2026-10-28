/*
 * The one clock usage reporting runs on.
 *
 * Replaceable because what is worth proving is about days: one report a day, none for a day missed, the day
 * figures of the day before. None of that is provable by waiting, and a fake timer would also move every
 * other clock in the process — token expiry, the interaction TTL — which a test of reporting does not mean
 * to change.
 */
let current: () => Date = () => new Date();

export function now(): Date {
	return current();
}

export function setClockForTests(clock: () => Date): () => void {
	const previous = current;
	current = clock;
	return () => {
		current = previous;
	};
}
