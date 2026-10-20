/*
 * What the creation step hands to the page it opens, once (spec 107): the secret that exists only in the answer that
 * minted it, and the API a service was set up to call. Held in this tab's memory only — never in the address, history
 * or storage — and forgotten once the page has it, so a reload or a second visit finds nothing.
 */
export interface HandOff {
	secret?: string;
	api?: string;
}

const pending = new Map<string, HandOff>();

export function handOff(clientId: string, value: HandOff): void {
	pending.set(clientId, value);
}

/*
 * Read in a state initialiser and forgotten in an effect, as two steps: in development React calls an initialiser
 * twice, and a read that also deleted would hand the page nothing on the call it keeps.
 */
export function peekHandOff(clientId: string): HandOff | undefined {
	return pending.get(clientId);
}

export function forgetHandOff(clientId: string): void {
	pending.delete(clientId);
}
