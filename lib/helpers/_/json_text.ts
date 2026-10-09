/*
 * JSON.stringify as it behaves: it answers undefined for undefined, a function or a symbol, though its
 * declaration says string. A caller with a fallback for that case states it against this, which neither
 * claims the fallback is dead nor needs an assertion to say it is not.
 */
export function jsonText(value: unknown): string | undefined {
	return JSON.stringify(value);
}
