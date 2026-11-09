import type { UserBucket } from '../adapters/types.js';
import {
	formatAddress,
	inAnyRange,
	isPublic,
	parseAddress,
	parseRanges,
	type Address
} from '../behind_proxy/net.js';
import { CLOUDFLARE_RANGES } from '../consts/cloudflare_ranges.js';
import { callerAddressOf, isTrustedProxy } from '../helpers/caller_address.js';
import { now } from '../telemetry/clock.js';
import { isExempt, listDecision, type ListDecision } from './decision.js';
import {
	noteListedFailure,
	noteListedRefusal,
	recentFailures
} from './local_failures.js';
import { listInEffect } from './state.js';

/*
 * The attacker list at a project's password door (specs/125 research R5, R7): which address is asked about, and what
 * the project's choice makes of it. Synchronous and in memory, so the door pays nothing for it.
 *
 * The address is the caller's (`callerAddressOf`), never one a request names. A trusted proxy's, a Cloudflare edge's,
 * an unattributed or a non-public one is never looked up: an instance whose caller address is misconfigured sees
 * every person as its proxy, and such an address must mean "nobody refused", never "everybody".
 */

const CLOUDFLARE = parseRanges(CLOUDFLARE_RANGES);

export interface GuessingAtDoor {
	readonly decision: ListDecision;
	/* The address asked about, as the person's own refusal page shows it; null when none was. */
	readonly address: Address | null;
	readonly shown: string | null;
	readonly dispute: string | null;
}

const NONE: GuessingAtDoor = {
	decision: 'none',
	address: null,
	shown: null,
	dispute: null
};

/* The address the list may be asked about, or null. */
export function listedCandidate(request: Request): Address | null {
	const caller = callerAddressOf(request);
	if (caller.from === 'unattributed') return null;
	if (isTrustedProxy(caller.address)) return null;
	const address = parseAddress(caller.address);
	if (!address || !isPublic(address) || inAnyRange(address, CLOUDFLARE)) {
		return null;
	}
	return address;
}

export function guessingAtDoor(
	request: Request,
	bucket: Pick<UserBucket, 'passwordGuessing'> | null
): GuessingAtDoor {
	const atMs = now().getTime();
	const list = listInEffect(atMs);
	if (!list) return NONE;
	const mode = bucket?.passwordGuessing?.mode ?? 'count';
	if (mode === 'nothing') return NONE;
	const address = listedCandidate(request);
	if (!address) return NONE;
	const exempt = isExempt(address, bucket?.passwordGuessing?.exempt, atMs);
	const decision = listDecision({
		inEffect: true,
		mode,
		entry: exempt ? null : list.matcher.lookup(address),
		exempt,
		recentFailures: recentFailures(address, atMs),
		nowSeconds: Math.floor(atMs / 1000)
	});
	return decision === 'none'
		? NONE
		: {
				decision,
				address,
				shown: formatAddress(address),
				dispute: list.dispute
			};
}

/*
 * A password failure at the door: tallied only for an address listed at this moment and outside the project's exempt
 * networks, in any mode, since the tally is the server's evidence and not the project's choice. Never throws.
 */
export function noteGuessingFailure(
	request: Request,
	bucket: Pick<UserBucket, 'passwordGuessing'> | null
): void {
	try {
		const atMs = now().getTime();
		const list = listInEffect(atMs);
		if (!list) return;
		const address = listedCandidate(request);
		if (!address) return;
		if (isExempt(address, bucket?.passwordGuessing?.exempt, atMs)) return;
		if (!list.matcher.lookup(address)) return;
		noteListedFailure(address, atMs);
	} catch {
		// Tallying is never a reason for a sign-in to fail.
	}
}

/* A refusal keeps the refusal going while the address keeps trying (FR-023). */
export function noteGuessingRefusal(guessing: GuessingAtDoor): void {
	if (guessing.address) noteListedRefusal(guessing.address, now().getTime());
}

/*
 * The line a refused person passes to the people who run the service: their own address, so an exemption can be made
 * without any address ever having been logged, and the time it happened.
 */
export function refusalLine(shown: string): string {
	const stamp = now().toISOString().slice(0, 16).replace('T', ' ');
	return `listed-address · ${shown} · ${stamp} UTC`;
}
