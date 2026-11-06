import { inAnyWindow, minuteOfWeek, type TimeWindow } from './clock.js';
import {
	inAnyRange,
	isPublic,
	parseAddress,
	parseRanges,
	type Address
} from './net.js';

/*
 * Conditions on top of "who" (specs/124): "and only if" added to a rule of an app behind the proxy or to an API
 * checked at the proxy. A condition only narrows; kinds combine with AND, values inside one kind with OR. Imports
 * only the two pure modules beside it, because the console bundles this with `decide()`.
 */

export type NetworkCondition = {
	kind: 'network';
	/* Canonical ranges; at least one of the two lists holds one, together at most MAX_RANGE_LINES. */
	only: string[];
	not: string[];
};
export type TimeCondition = { kind: 'time'; windows: TimeWindow[] };
export type AttributeCondition = {
	kind: 'attribute';
	attribute: string;
	values: string[];
};
export type FreshCondition = { kind: 'fresh'; maxAgeMinutes: number };
export type GroupCondition = { kind: 'group'; groupIds: string[] };

export type Condition =
	| NetworkCondition
	| TimeCondition
	| AttributeCondition
	| FreshCondition
	| GroupCondition;

export type ConditionKind = Condition['kind'];

export const MAX_RANGE_LINES = 100;
export const MAX_WINDOWS = 7;
export const MAX_ATTRIBUTE_VALUES = 50;
export const MAX_ATTRIBUTE_VALUE = 200;
export const MIN_FRESH_MINUTES = 5;
export const MAX_FRESH_MINUTES = 1440;

/* Attributes an administrator or a provisioning connection sets, and nothing a person sets at a provider. */
export const PROFILE_ATTRIBUTES = [
	'department',
	'division',
	'organization',
	'costCenter',
	'employeeNumber',
	'title'
] as const;
export const CLAIM_PREFIX = 'claim:';
export const CLAIM_KEY = /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/;
/*
 * Claims an outside sign-in provider copies into the person's record (lib/federation/consts.ts COPIED_CLAIMS) are
 * written by the person at that provider, and the ones the server issues itself are not attributes; a condition on
 * either would let someone qualify by editing their own profile (specs/124 FR-014).
 */
export const NOT_SELECTABLE_CLAIMS = [
	'name',
	'given_name',
	'family_name',
	'picture',
	'locale',
	'sub',
	'email',
	'email_verified',
	'groups'
] as const;

export function isSelectableAttribute(name: string): boolean {
	if ((PROFILE_ATTRIBUTES as readonly string[]).includes(name)) return true;
	if (!name.startsWith(CLAIM_PREFIX)) return false;
	const key = name.slice(CLAIM_PREFIX.length);
	return (
		CLAIM_KEY.test(key) &&
		!(NOT_SELECTABLE_CLAIMS as readonly string[]).includes(key)
	);
}

export type ConditionResult = 'pass' | 'fail' | 'unknown';

/* What a condition is judged on. A null input is one the console's "Check access" was not given. */
export interface Facts {
	/* The address the check believed (specs/124 FR-006), as text. */
	address: string | null;
	/* Epoch milliseconds. */
	at: number | null;
	timeZone: string | null;
	person: {
		groupIds: readonly string[];
		attributes?: Readonly<Record<string, string>>;
		/* Epoch seconds of the person's sign-in. */
		signedInAt?: number | null;
	} | null;
	/* The console: an input not given is "unknown" instead of failing. */
	explain: boolean;
}

function missing(explain: boolean): ConditionResult {
	return explain ? 'unknown' : 'fail';
}

function network(
	condition: NetworkCondition,
	text: string | null,
	explain: boolean
): ConditionResult {
	if (text === null) return missing(explain);
	const address: Address | null = parseAddress(text);
	if (!address) return 'fail';
	const only = parseRanges(condition.only);
	const not = parseRanges(condition.not);
	if (only.length > 0 && !inAnyRange(address, only)) return 'fail';
	if (not.length > 0) {
		if (inAnyRange(address, not)) return 'fail';
		/*
		 * An address of the proxy's own network says nothing about where the person is, so it is not taken as being
		 * outside the list — unless the condition names it, which is the operator saying what it means here.
		 */
		if (!isPublic(address) && !inAnyRange(address, only)) return 'fail';
	}
	return 'pass';
}

export function evaluate(condition: Condition, facts: Facts): ConditionResult {
	const { explain } = facts;
	switch (condition.kind) {
		case 'network':
			return network(condition, facts.address, explain);
		case 'time': {
			if (facts.at === null || facts.timeZone === null) {
				return missing(explain);
			}
			return inAnyWindow(
				condition.windows,
				minuteOfWeek(facts.at, facts.timeZone)
			)
				? 'pass'
				: 'fail';
		}
		case 'attribute': {
			if (!facts.person) return 'unknown';
			const value = facts.person.attributes?.[condition.attribute];
			return value !== undefined && condition.values.includes(value)
				? 'pass'
				: 'fail';
		}
		case 'group': {
			if (!facts.person) return 'unknown';
			return condition.groupIds.some((id) =>
				facts.person?.groupIds.includes(id)
			)
				? 'pass'
				: 'fail';
		}
		case 'fresh': {
			if (!facts.person) return 'unknown';
			const signedInAt = facts.person.signedInAt ?? null;
			if (signedInAt === null || facts.at === null) return missing(explain);
			return facts.at - signedInAt * 1000 <= condition.maxAgeMinutes * 60_000
				? 'pass'
				: 'fail';
		}
	}
}

export interface Judged {
	condition: Condition;
	/* The rule path the condition belongs to, or `api`. */
	from: string;
	result: ConditionResult;
}

/* The order conditions are decided in, which is also the order "Check access" lists them in (research R2). */
export const APP_ORDER: readonly ConditionKind[] = [
	'network',
	'time',
	'attribute',
	'fresh'
];
export const API_ORDER: readonly ConditionKind[] = [
	'group',
	'attribute',
	'network',
	'time'
];

export function inOrder<T extends { condition: Condition }>(
	items: readonly T[],
	order: readonly ConditionKind[]
): T[] {
	return [...items].sort(
		(a, b) => order.indexOf(a.condition.kind) - order.indexOf(b.condition.kind)
	);
}

export type AccessRefusal =
	| 'no_person'
	| 'not_in_group'
	| 'attribute_mismatch'
	| 'not_from_network'
	| 'outside_hours';

const REFUSAL_OF: Record<ConditionKind, AccessRefusal> = {
	group: 'not_in_group',
	attribute: 'attribute_mismatch',
	network: 'not_from_network',
	time: 'outside_hours',
	/* Never on an API: freshness belongs to an app's session. */
	fresh: 'not_from_network'
};

/*
 * An API's access conditions over a token (specs/124 FR-015, FR-016): the person first — a token that stands for
 * nobody fails every condition about a person — then the API order. Null when every condition holds.
 */
export function decideAccess(
	conditions: readonly Condition[],
	facts: Facts
): AccessRefusal | null {
	const aboutPerson = conditions.some(
		(c) => c.kind === 'group' || c.kind === 'attribute'
	);
	if (aboutPerson && !facts.person) return 'no_person';
	for (const condition of inOrder(
		conditions.map((c) => ({ condition: c })),
		API_ORDER
	)) {
		if (evaluate(condition.condition, facts) !== 'pass') {
			return REFUSAL_OF[condition.condition.kind];
		}
	}
	return null;
}

/*
 * The values an attribute condition may name, read off a person's record or the admin view of it (FR-014): the
 * enterprise profile, the title, and claims as strings only. A claim a provider copies in is excluded by the
 * condition, never here, so a count and a decision read the same values.
 */
export function attributesOfRecord(person: {
	profile?: {
		title?: unknown;
		enterprise?: Readonly<Record<string, unknown>>;
	};
	claims?: Readonly<Record<string, unknown>>;
}): Record<string, string> {
	const out: Record<string, string> = {};
	const enterprise = person.profile?.enterprise;
	for (const name of PROFILE_ATTRIBUTES) {
		if (name === 'title') continue;
		const value = enterprise?.[name];
		if (typeof value === 'string') out[name] = value;
	}
	if (typeof person.profile?.title === 'string')
		out.title = person.profile.title;
	for (const [key, value] of Object.entries(person.claims ?? {})) {
		if (typeof value === 'string') out[`${CLAIM_PREFIX}${key}`] = value;
	}
	return out;
}
