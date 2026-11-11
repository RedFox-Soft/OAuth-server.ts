import { weekBitmap } from './clock.js';
import type {
	Condition,
	ConditionKind,
	NetworkFactsPart
} from './conditions.js';
import { coveredBy, overlapsNotPublic, parseRanges } from './net.js';

/*
 * Whether a change of conditions lets more requests through (specs/124 research R11). Probing by result, as
 * `widenings()` does for "who", cannot cover addresses and minutes, so conditions are compared by what they admit:
 * each condition a path had before must be matched by one it has after that admits no more. That is sound — whatever
 * passes every condition after passes each matched one, so passes every condition before — and may report a change
 * that is not a widening when several conditions together are as strict as one was; a confirmation too many is the
 * safe side to err on. Imports only the pure modules beside it: the console bundles it.
 */

export interface Loosened {
	kind: ConditionKind;
	/* The condition that no longer holds as strictly, as it was before. */
	before: Condition;
}

function rangesWithin(
	narrow: readonly string[],
	wide: readonly string[]
): boolean {
	const outer = parseRanges(wide);
	return parseRanges(narrow).every((range) => coveredBy(range, outer));
}

/*
 * Whether a network facts part admits no address `before` refuses (specs/129 data-model §9). Unknown facts close
 * either the same way, so only what a known address meets is compared: categories kept out, countries, and what a
 * match leads to.
 */
function factsAtLeastAsStrict(
	before: NetworkFactsPart | undefined,
	after: NetworkFactsPart | undefined
): boolean {
	if (!before) return true;
	if (!after) return false;
	if (!before.categories.every((c) => after.categories.includes(c))) {
		return false;
	}
	const was = before.countries;
	const now = after.countries;
	if (was) {
		if (!now) return false;
		if (was.mode === 'only') {
			if (now.mode !== 'only') return false;
			if (!now.codes.every((code) => was.codes.includes(code))) return false;
		} else if (now.mode === 'not') {
			if (!was.codes.every((code) => now.codes.includes(code))) return false;
		} else if (now.codes.some((code) => was.codes.includes(code))) {
			/* "Only from" admits no address without a country, so it is stricter than "not from" unless it names one. */
			return false;
		}
	}
	const a = before.outcome;
	const b = after.outcome;
	if (b.kind === 'refuse') return true;
	if (a.kind === 'refuse') return false;
	return (
		b.maxAgeMinutes <= a.maxAgeMinutes &&
		(a.withCode !== true || b.withCode === true)
	);
}

/* Whether `after` admits no request `before` refuses, for two conditions of one kind. */
function atLeastAsStrict(
	before: Condition,
	after: Condition,
	sameZone: boolean
): boolean {
	switch (before.kind) {
		case 'network': {
			if (after.kind !== 'network') return false;
			/* An empty "only" admits every address; a non-empty one admits only its ranges. */
			const onlyHolds =
				before.only.length === 0 ||
				(after.only.length > 0 && rangesWithin(after.only, before.only));
			const notHolds = rangesWithin(before.not, after.not);
			/*
			 * Not from also turns away the proxy's own network unless "only" names it: dropping every Not from range
			 * admits that network, and so does naming a part of it in "only" that "only" did not name before.
			 */
			const before0 = parseRanges(before.only);
			const privateHolds =
				before.not.length === 0 ||
				(after.not.length > 0 &&
					parseRanges(after.only).every(
						(range) => !overlapsNotPublic(range) || coveredBy(range, before0)
					));
			return (
				onlyHolds &&
				notHolds &&
				privateHolds &&
				factsAtLeastAsStrict(before.facts, after.facts)
			);
		}
		case 'time': {
			if (after.kind !== 'time' || !sameZone) return false;
			const was = weekBitmap(before.windows);
			const now = weekBitmap(after.windows);
			for (let minute = 0; minute < now.length; minute++) {
				if (now[minute] && !was[minute]) return false;
			}
			return true;
		}
		case 'attribute':
			return (
				after.kind === 'attribute' &&
				after.attribute === before.attribute &&
				after.values.every((value) => before.values.includes(value))
			);
		case 'fresh':
			/* Dropping the code (specs/128) admits a sign-in without one, however recent. */
			return (
				after.kind === 'fresh' &&
				after.maxAgeMinutes <= before.maxAgeMinutes &&
				(before.withCode !== true || after.withCode === true)
			);
		case 'group':
			return (
				after.kind === 'group' &&
				after.groupIds.every((id) => before.groupIds.includes(id))
			);
	}
}

/*
 * The conditions a path had before that nothing it has after holds as strictly. `sameZone` is false when the time
 * zone the windows are read in changed, which moves every window and so loosens every time condition.
 */
export function loosenedConditions(
	before: readonly Condition[],
	after: readonly Condition[],
	sameZone = true
): Loosened[] {
	return before
		.filter(
			(was) =>
				!after.some(
					(now) => now.kind === was.kind && atLeastAsStrict(was, now, sameZone)
				)
		)
		.map((was) => ({ kind: was.kind, before: was }));
}
