import { inRange, parseRange, type Address } from '../behind_proxy/net.js';
import type {
	PasswordGuessingExemption,
	PasswordGuessingMode
} from '../adapters/types.js';
import {
	LOCAL_FAILURE_THRESHOLD,
	REFUSE_RECENCY_SECONDS
} from '../consts/attacker_list.js';
import type { ListEntry } from './matcher.js';

/*
 * What a password sign-in from one address meets (specs/125 research R7), as one pure function so the page, the
 * handler and the tests cannot disagree.
 *
 * - `none`: the list is not in effect, the project chose nothing, the address is exempt or not listed;
 * - `refuse`: the project refuses, the entry was seen in the last 48 hours, and FoxTrust corroborates it or this
 *   process saw it fail passwords enough times in the last hour — the owner's rule, also stated on FoxTrust's page;
 * - `count`: listed, and nothing above refuses it.
 */

export type ListDecision = 'none' | 'count' | 'refuse';

export interface DecisionInput {
	readonly inEffect: boolean;
	readonly mode: PasswordGuessingMode;
	readonly entry: ListEntry | null;
	readonly exempt: boolean;
	/* Password failures (and refusals) from this address seen by this process within the window. */
	readonly recentFailures: number;
	readonly nowSeconds: number;
}

export function listDecision(input: DecisionInput): ListDecision {
	if (!input.inEffect || input.mode === 'nothing' || input.exempt) {
		return 'none';
	}
	const entry = input.entry;
	if (!entry) return 'none';
	if (input.mode !== 'refuse') return 'count';
	const recent = input.nowSeconds - entry.lastSeen <= REFUSE_RECENCY_SECONDS;
	if (
		recent &&
		(entry.corroborated || input.recentFailures >= LOCAL_FAILURE_THRESHOLD)
	) {
		return 'refuse';
	}
	return 'count';
}

/* Whether a network the project exempts covers `address` at `nowMs`; an exemption past its `until` no longer does. */
export function isExempt(
	address: Address,
	exempt: readonly PasswordGuessingExemption[] | undefined,
	nowMs: number
): boolean {
	for (const entry of exempt ?? []) {
		if (entry.until !== undefined && Date.parse(entry.until) <= nowMs) {
			continue;
		}
		const range = parseRange(entry.network);
		if (!('error' in range) && inRange(address, range)) return true;
	}
	return false;
}
