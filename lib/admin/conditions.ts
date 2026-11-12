import {
	adapter,
	getBucketGroupStore,
	getUserStore
} from '../adapters/index.js';
import type {
	ApiAccess,
	BehindProxyWho,
	RowCondition,
	UserBucket
} from '../adapters/types.js';
import { canonicalTimeZone } from '../behind_proxy/clock.js';
import {
	isSelectableAttribute,
	MAX_FRESH_MINUTES,
	MAX_RANGE_LINES,
	MIN_FRESH_MINUTES,
	type Condition,
	type ConditionKind,
	type NetworkCategory,
	type NetworkFactsPart
} from '../behind_proxy/conditions.js';
import { ApplicationConfig } from '../configs/application.js';
import { isCountryCode } from '../consts/countries.js';
import { MAX_COUNTRIES, NETWORK_CATEGORIES } from '../consts/network_facts.js';
import { formatRange, parseRange } from '../behind_proxy/net.js';
import { AdminError } from './auth/rbac.js';

/*
 * The rules about conditions at the proxy (specs/124 contracts/admin-api.md) that a closed schema cannot state, in one
 * place an app's rules and an API's access both pass through: ranges stored in the one canonical form the check
 * compares against, attributes a person cannot set themselves, groups of this project, windows on the quarter hour.
 * Each refusal names the place and the value, as the console shows it.
 */

/*
 * A condition as a body carries it (lib/admin/behind-proxy/schema.ts), written out structurally because the
 * schema's static type reaches this module through Elysia's copy of TypeBox and not this one.
 */
export interface NetworkFactsInput {
	categories: string[];
	countries?: { mode: 'only' | 'not'; codes: string[] };
	outcome:
		| { kind: 'refuse' }
		| { kind: 'sign_in_again'; maxAgeMinutes: number; withCode?: boolean };
}

export type ConditionInput =
	| {
			kind: 'network';
			only: string[];
			not: string[];
			facts?: NetworkFactsInput;
	  }
	| {
			kind: 'time';
			windows: { days: number[]; start: number; end: number }[];
	  }
	| { kind: 'attribute'; attribute: string; values: string[] }
	| { kind: 'fresh'; maxAgeMinutes: number; withCode?: boolean }
	| { kind: 'group'; groups: string[] };

const RANGE_PROBLEMS = {
	malformed: 'is not an address or a range such as 203.0.113.0/24',
	host_bits:
		'has bits set after its prefix; write the network address, such as 203.0.113.0/24',
	everything: 'would match every address there is'
} as const;

function refuse(message: string, field: string): AdminError {
	return new AdminError(422, message, { field });
}

function canonicalRanges(
	lines: readonly string[],
	where: string,
	field: string
): string[] {
	const out: string[] = [];
	for (const line of lines) {
		const text = line.trim();
		const range = parseRange(text);
		if ('error' in range) {
			throw refuse(`${where}: ${text} ${RANGE_PROBLEMS[range.error]}`, field);
		}
		const canonical = formatRange(range);
		if (!out.includes(canonical)) out.push(canonical);
	}
	return out;
}

async function projectGroupIds(
	bucket: UserBucket,
	ids: readonly string[],
	where: string,
	field: string
): Promise<string[]> {
	const unique = [...new Set(ids)];
	const found = await getBucketGroupStore().findMany(unique);
	const ours = new Set(
		found.filter((g) => g.bucketId === bucket._id).map((g) => g._id)
	);
	for (const id of unique) {
		if (!ours.has(id)) {
			throw refuse(
				`${where}: group ${id} is not a group of this project`,
				field
			);
		}
	}
	return unique;
}

/*
 * The network facts part as stored (specs/129 data-model §7): categories in one order, countries upper case and
 * sorted, the code stored only when on. On an API only Refuse: a token check has no sign-in to ask for (FR-021).
 */
function networkFactsFrom(
	input: NetworkFactsInput,
	target: 'app' | 'api',
	where: string,
	field: string
): NetworkFactsPart {
	const categories: NetworkCategory[] = [];
	for (const category of input.categories) {
		const known = NETWORK_CATEGORIES.find((c) => c === category);
		if (!known) {
			throw refuse(
				`${where}: ${category} is not a network fact; use tor, vpn or hosting`,
				field
			);
		}
		if (!categories.includes(known)) categories.push(known);
	}
	categories.sort(
		(a, b) => NETWORK_CATEGORIES.indexOf(a) - NETWORK_CATEGORIES.indexOf(b)
	);
	let countries: NetworkFactsPart['countries'];
	if (input.countries) {
		const codes = [
			...new Set(input.countries.codes.map((c) => c.trim().toUpperCase()))
		];
		for (const code of codes) {
			if (!isCountryCode(code)) {
				throw refuse(
					`${where}: ${code} is not a country code; use two letters such as DE`,
					field
				);
			}
		}
		if (codes.length === 0 || codes.length > MAX_COUNTRIES) {
			throw refuse(
				`${where}: list between 1 and ${String(MAX_COUNTRIES)} countries`,
				field
			);
		}
		countries = { mode: input.countries.mode, codes: codes.sort() };
	}
	if (categories.length === 0 && !countries) {
		throw refuse(
			`${where}: choose at least one network or country to keep out or in`,
			field
		);
	}
	let outcome: NetworkFactsPart['outcome'];
	if (input.outcome.kind === 'refuse') {
		outcome = { kind: 'refuse' };
	} else {
		if (target === 'api') {
			throw refuse(
				`${where}: an API can only refuse a matching address; there is no sign-in to ask for`,
				field
			);
		}
		const minutes = input.outcome.maxAgeMinutes;
		if (
			!Number.isInteger(minutes) ||
			minutes < MIN_FRESH_MINUTES ||
			minutes > MAX_FRESH_MINUTES
		) {
			throw refuse(
				`${where}: sign in again within ${String(MIN_FRESH_MINUTES)} minutes to 24 hours`,
				field
			);
		}
		outcome = {
			kind: 'sign_in_again',
			maxAgeMinutes: minutes,
			...(input.outcome.withCode === true ? { withCode: true as const } : {})
		};
	}
	return { categories, ...(countries ? { countries } : {}), outcome };
}

/*
 * The conditions as they are stored, or a refusal. `where` names the place for the message (`/admin and below`, the
 * API's name); `field` is the body field the console puts the message on.
 */
export async function conditionsFrom(
	bucket: UserBucket,
	input: readonly ConditionInput[],
	where: string,
	field: string,
	target: 'app' | 'api' = 'app'
): Promise<Condition[]> {
	const seen = new Set<ConditionKind>();
	const out: Condition[] = [];
	for (const condition of input) {
		if (seen.has(condition.kind)) {
			throw refuse(
				`${where}: only one ${condition.kind} condition; list several values in it instead`,
				field
			);
		}
		seen.add(condition.kind);
		switch (condition.kind) {
			case 'network': {
				const only = canonicalRanges(condition.only, where, field);
				const not = canonicalRanges(condition.not, where, field);
				const facts = condition.facts
					? networkFactsFrom(condition.facts, target, where, field)
					: undefined;
				if (only.length + not.length === 0 && !facts) {
					throw refuse(
						`${where}: list at least one address, range, network or country`,
						field
					);
				}
				if (only.length + not.length > MAX_RANGE_LINES) {
					throw refuse(
						`${where}: at most ${String(MAX_RANGE_LINES)} addresses and ranges`,
						field
					);
				}
				out.push({ kind: 'network', only, not, ...(facts ? { facts } : {}) });
				break;
			}
			case 'time': {
				for (const window of condition.windows) {
					if (new Set(window.days).size !== window.days.length) {
						throw refuse(`${where}: a day is listed twice in a window`, field);
					}
					if (window.start % 15 !== 0 || window.end % 15 !== 0) {
						throw refuse(
							`${where}: windows start and end on the quarter hour`,
							field
						);
					}
					if (window.start === window.end) {
						throw refuse(
							`${where}: a window that ends when it starts is never open`,
							field
						);
					}
				}
				out.push({
					kind: 'time',
					windows: condition.windows.map((w) => ({
						days: [...w.days].sort((a, b) => a - b),
						start: w.start,
						end: w.end
					}))
				});
				break;
			}
			case 'attribute': {
				if (!isSelectableAttribute(condition.attribute)) {
					throw refuse(
						`${where}: ${condition.attribute} cannot be used in a condition; use department, division, organization, costCenter, employeeNumber, title or claim:<key> for a claim an administrator sets`,
						field
					);
				}
				out.push({
					kind: 'attribute',
					attribute: condition.attribute,
					values: [...new Set(condition.values)]
				});
				break;
			}
			case 'fresh':
				/* Stored only when on, so a condition without it is the record it always was (specs/128 R1). */
				out.push({
					kind: 'fresh',
					maxAgeMinutes: condition.maxAgeMinutes,
					...(condition.withCode === true ? { withCode: true as const } : {})
				});
				break;
			case 'group':
				out.push({
					kind: 'group',
					groupIds: await projectGroupIds(
						bucket,
						condition.groups,
						where,
						field
					)
				});
				break;
		}
	}
	return out;
}

type ApiCondition = ApiAccess['conditions'][number];
type AppCondition = Extract<
	BehindProxyWho,
	{ kind: 'conditional' }
>['conditions'][number];

/* An API's conditions as stored; the body's schema already allows no fresh sign-in on an API. */
export function apiConditionsOf(
	conditions: readonly Condition[]
): ApiCondition[] {
	return conditions.filter((c): c is ApiCondition => c.kind !== 'fresh');
}

/* A tool row's conditions as stored; the body's schema already allows only group, network and time on a row. */
export function rowConditionsOf(
	conditions: readonly Condition[]
): RowCondition[] {
	return conditions.filter(
		(c): c is RowCondition =>
			c.kind === 'group' || c.kind === 'network' || c.kind === 'time'
	);
}

/* An app rule's conditions as stored; the body's schema already allows no group condition on an app. */
export function appConditionsOf(
	conditions: readonly Condition[]
): AppCondition[] {
	return conditions.filter((c): c is AppCondition => c.kind !== 'group');
}

/* The zone as stored, or a refusal; null clears it. */
export function timeZoneFrom(
	input: string | null,
	field: string
): string | null {
	if (input === null) return null;
	const zone = canonicalTimeZone(input.trim());
	if (!zone) {
		throw refuse(
			`${input} is not a time zone; use an IANA name such as Europe/Moscow`,
			field
		);
	}
	return zone;
}

/* How many people of the project an attribute condition lets through (specs/124 FR-014). */
export async function attributeMatches(
	bucket: UserBucket,
	attribute: string,
	values: readonly string[]
): Promise<number> {
	const result = await getUserStore(bucket._id).query(
		{ attribute: { name: attribute, values } },
		{ startIndex: 1, count: 1 }
	);
	return result.totalResults;
}

/*
 * The 409s a save must answer before it is recorded: a network condition the proxy has not proved it can feed, and an
 * attribute condition nobody in the project meets. Only conditions that are new or changed are judged, so an
 * unrelated edit never finds a saved condition unsavable.
 */
export async function assertConditionsUsable(
	bucket: UserBucket,
	before: readonly Condition[],
	after: readonly Condition[],
	proof: { provenAt?: Date; forgedAt?: Date },
	where: string,
	field: string
): Promise<void> {
	const changed = after.filter(
		(condition) =>
			!before.some((old) => JSON.stringify(old) === JSON.stringify(condition))
	);
	for (const condition of changed) {
		if (
			condition.kind === 'network' &&
			condition.facts &&
			!ApplicationConfig['networkFacts.enabled'] &&
			!before.some(
				(old) =>
					old.kind === 'network' &&
					JSON.stringify(old.facts) === JSON.stringify(condition.facts)
			)
		) {
			/* Saved ones stay when the download goes off (FR-015); a new or changed one waits for it. */
			throw new AdminError(
				409,
				`${where}: network facts are off on this server, so this condition would close the path. A super administrator turns them on in Settings → Integrations.`,
				{ field, code: 'network_facts_off' }
			);
		}
		if (condition.kind === 'network') {
			const { provenAt, forgedAt } = proof;
			if (!provenAt || (forgedAt && forgedAt >= provenAt)) {
				throw new AdminError(
					409,
					"Your proxy hasn't shown it passes people's addresses yet. Saving now would turn everyone away. Finish the step \"Your proxy passes people's addresses\" on Connect first.",
					{ field, code: 'proxy_address_unproven' }
				);
			}
		}
		if (condition.kind === 'attribute') {
			const count = await attributeMatches(
				bucket,
				condition.attribute,
				condition.values
			);
			if (count === 0) {
				throw new AdminError(
					409,
					`${where}: nobody in this project has ${condition.attribute} equal to ${condition.values.join(' or ')}, so this condition would turn everyone away.`,
					{ field, code: 'attribute_matches_nobody' }
				);
			}
		}
	}
}

/*
 * Who an API condition about the person would turn away without anyone being at fault (specs/124 FR-018): the
 * project's applications that receive tokens for no person, and those whose subjects are pairwise, which the check
 * cannot trace back to a person. Named, so an administrator recognises them before saving.
 */
export async function personConditionWarnings(bucketId: string): Promise<{
	machineClients: string[];
	pairwiseClients: string[];
}> {
	const stored = await adapter('Client').findByIndexed('bucketId', bucketId);
	const nameOf = (record: Record<string, unknown>) =>
		typeof record.clientName === 'string' && record.clientName !== ''
			? record.clientName
			: String(record.clientId);
	const machineClients: string[] = [];
	const pairwiseClients: string[] = [];
	for (const record of stored as Record<string, unknown>[]) {
		const grants = Array.isArray(record.grantTypes) ? record.grantTypes : [];
		if (grants.includes('client_credentials'))
			machineClients.push(nameOf(record));
		if (record.subjectType === 'pairwise') pairwiseClients.push(nameOf(record));
	}
	return {
		machineClients: machineClients.sort(),
		pairwiseClients: pairwiseClients.sort()
	};
}
