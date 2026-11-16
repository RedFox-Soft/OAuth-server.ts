import {
	formatAddress,
	isPublic,
	parseAddress,
	type Address
} from '../behind_proxy/net.js';
import {
	isTrustedProxy,
	type CallerAddress
} from '../helpers/caller_address.js';
import { factsAt } from '../network_facts/state.js';
import type { PersonActivityRow } from '../adapters/types.js';

type Facts = NonNullable<PersonActivityRow['facts']>;

/*
 * The address a sign-in is recorded with (specs/133 research R6): the caller as this server attributes it, the same
 * rule its rate limits use, in full. `parseAddress` reads an IPv4-mapped IPv6 address as its IPv4 address, so a
 * dual-stack socket does not turn every IPv4 person into one IPv6 network. Not recorded: a request with no
 * connection, an address that is not on the public Internet (a container bridge, a load balancer), and the address
 * of a proxy this server trusts, which is a hop and never the person.
 */
export function personAddressOf(caller: CallerAddress): Address | null {
	if (caller.from === 'unattributed') return null;
	const parsed = parseAddress(caller.address);
	if (!parsed || !isPublic(parsed)) return null;
	const text = formatAddress(parsed);
	if (isTrustedProxy(text)) return null;
	return parsed;
}

/*
 * FoxTrust's country and categories for an address, from this process's own copy of the snapshot (research R7):
 * nothing is sent anywhere, and nothing but the country and the categories is read. Undefined whenever the facts are
 * off, not loaded or stale, so no row ever says "unknown country".
 */
export function factsOf(address: Address, nowMs: number): Facts | undefined {
	const facts = factsAt(address, nowMs);
	if (!facts.known) return undefined;
	return {
		...(facts.country === null ? {} : { country: facts.country }),
		categories: [...facts.categories]
	};
}

export { formatAddress };
