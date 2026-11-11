import {
	adapter,
	getBucketGroupStore,
	getUserStore
} from '../adapters/index.js';
import type {
	ApiAccess,
	BehindProxyWho,
	UserBucket
} from '../adapters/types.js';
import { canonicalTimeZone } from '../behind_proxy/clock.js';
import {
	isSelectableAttribute,
	MAX_RANGE_LINES,
	type Condition,
	type ConditionKind
} from '../behind_proxy/conditions.js';
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
export type ConditionInput =
	| { kind: 'network'; only: string[]; not: string[] }
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
 * The conditions as they are stored, or a refusal. `where` names the place for the message (`/admin and below`, the
 * API's name); `field` is the body field the console puts the message on.
 */
export async function conditionsFrom(
	bucket: UserBucket,
	input: readonly ConditionInput[],
	where: string,
	field: string
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
				if (only.length + not.length === 0) {
					throw refuse(`${where}: list at least one address or range`, field);
				}
				if (only.length + not.length > MAX_RANGE_LINES) {
					throw refuse(
						`${where}: at most ${String(MAX_RANGE_LINES)} addresses and ranges`,
						field
					);
				}
				out.push({ kind: 'network', only, not });
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
