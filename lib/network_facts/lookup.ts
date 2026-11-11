import type { Condition, NetworkFacts } from '../behind_proxy/conditions.js';
import { parseAddress } from '../behind_proxy/net.js';
import { now } from '../telemetry/clock.js';
import { factsAt } from './state.js';

/*
 * The network facts a check hands to the decision (specs/129 FR-016, FR-017): only for the address the check believed,
 * only when some condition asks for them, and as facts, never as the snapshot. No believed address, no facts: the
 * condition then fails as "From where" does today.
 */
export function factsForBelieved(
	address: string | null,
	conditions: readonly Condition[]
): NetworkFacts | undefined {
	if (address === null) return undefined;
	if (!conditions.some((c) => c.kind === 'network' && c.facts))
		return undefined;
	const parsed = parseAddress(address);
	if (!parsed) return undefined;
	return factsAt(parsed, now().getTime());
}
