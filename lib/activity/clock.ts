/*
 * The one clock activity is counted against.
 *
 * Replaceable because the properties worth proving are about months: a closed month stays as it was after
 * the next one starts, a mark outlives its month by thirteen months and then goes. None of that is provable
 * by waiting, and a fake timer would also move every other clock in the process — token expiry, the
 * interaction TTL — which is not what a test of counting means to change.
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
