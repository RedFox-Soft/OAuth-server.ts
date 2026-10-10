import type { ActivityTally } from '../adapters/types.js';
import type { PeriodFigure } from './read.js';

/*
 * The super administrator's usage overview (specs/077): the shape of `GET /admin/api/activity` and the
 * arithmetic over it.
 *
 * Declared once and imported by both the route and the console. The route computes every total over every
 * bucket, which is the agent's answer; the console computes the same totals again over the rows its search
 * and filters leave, so a total on screen always describes exactly the rows on screen. One set of functions
 * for both is what keeps the console's numbers and the agent's from ever disagreeing.
 *
 * Type-only imports: this module is bundled into the console, which must not reach the adapters.
 */

export type GroupKind = 'personal' | 'regular' | 'system';

/*
 * Who a bucket belongs to, as a reader is shown it. `groupId` is null only when nobody recorded the owner —
 * a bucket deleted before owners were kept. `exists` says whether the group can still be opened: false for
 * that unknown owner and for a deleted bucket's group that has since been deleted too.
 */
export interface CustomerRef {
	groupId: string | null;
	label: string;
	kind: GroupKind | null;
	exists: boolean;
}

export interface OverviewRow {
	bucketId: string;
	name: string;
	slug: string | null;
	reserved: 'default' | 'administrators' | null;
	deleted: string | null;
	/* Spec 076's two figures, kept for readers written against it: `months[0]` and `months[1]`. */
	current: PeriodFigure | null;
	previous: PeriodFigure | null;
	customer: CustomerRef;
	/* Index 0 is the month asked for, index 12 the twelfth before it; aligned with the answer's `months`. */
	months: (PeriodFigure | null)[];
	days: (number | null)[];
	previousDays: (number | null)[];
	unavailable: boolean;
}

/*
 * A sum of bucket figures. Never a count of distinct people: every bucket is its own population with its
 * own accounts, so a person in two buckets is two accounts and is in two figures.
 */
export interface Sum extends ActivityTally {
	final: boolean;
	partial: boolean;
	unavailable: number;
}

export interface Change {
	absolute: number;
	percent: number | null;
}

export interface CustomerSummary {
	customer: CustomerRef;
	contacts: string[];
	memberCount: number;
	bucketIds: string[];
	current: Sum | null;
	previous: Sum | null;
}

export interface InstanceSummary {
	months: (Sum | null)[];
	days: (number | null)[];
	previousDays: (number | null)[];
	activeBuckets: number;
	activeCustomers: number;
	today: number | null;
	change: Change | null;
}

export interface SharpChange {
	bucketId: string;
	name: string;
	customer: CustomerRef;
	from: { period: string; total: number };
	to: { period: string; total: number };
	absolute: number;
	percent: number | null;
}

export interface SharpChanges {
	from: string | null;
	to: string | null;
	falls: SharpChange[];
	rises: SharpChange[];
}

export interface OverviewAnswer {
	month: string;
	previous: string;
	asOf: string;
	countingSince: string;
	months: string[];
	daysFinal: boolean[];
	buckets: OverviewRow[];
	customers: CustomerSummary[];
	instance: InstanceSummary;
	changes: SharpChanges;
}

export interface CustomerDetails {
	contacts: string[];
	memberCount: number;
}

/*
 * A change is sharp when it moves at least this many people and at least this share of the earlier
 * figure. Both, so neither a bucket of three people losing two nor a bucket of a million gaining twenty is
 * news. Fixed rather than settings until an operator shows a need to tune them (specs/077, Assumptions).
 */
export const SHARP_CHANGE_MIN_PEOPLE = 20;
export const SHARP_CHANGE_MIN_SHARE = 0.3;

const UNKNOWN_CUSTOMER_KEY = '\u0000unknown';

export function customerKey(customer: CustomerRef): string {
	return customer.groupId ?? UNKNOWN_CUSTOMER_KEY;
}

/*
 * `null` when nothing was there to sum — every figure absent — so a period before any bucket existed reads
 * as absent rather than as zero. Final only when every summed figure is: one figure that may still grow
 * makes the sum one that may still grow.
 */
export function sumFigures(
	figures: readonly (ActivityTally & { final: boolean })[],
	absent: number,
	unavailable: number
): Sum | null {
	if (figures.length === 0) return null;
	const sum: Sum = {
		total: 0,
		byKind: { local: 0, federated: 0, renewal: 0 },
		provisioned: 0,
		final: true,
		partial: absent > 0 || unavailable > 0,
		unavailable
	};
	for (const figure of figures) {
		sum.total += figure.total;
		sum.byKind.local += figure.byKind.local;
		sum.byKind.federated += figure.byKind.federated;
		sum.byKind.renewal += figure.byKind.renewal;
		sum.provisioned += figure.provisioned;
		if (!figure.final) sum.final = false;
	}
	return sum;
}

/* The rows' figures at one month index, summed. */
export function sumMonth(
	rows: readonly OverviewRow[],
	index: number
): Sum | null {
	const present: PeriodFigure[] = [];
	let absent = 0;
	let unavailable = 0;
	for (const row of rows) {
		if (row.unavailable) {
			unavailable += 1;
			continue;
		}
		const figure = row.months[index] ?? null;
		if (figure === null) absent += 1;
		else present.push(figure);
	}
	return sumFigures(present, absent, unavailable);
}

function sumDays(
	series: readonly (readonly (number | null)[])[]
): (number | null)[] {
	const length = Math.max(0, ...series.map((days) => days.length));
	return Array.from({ length }, (_, day) => {
		let total: number | null = null;
		for (const days of series) {
			const value = days[day] ?? null;
			if (value !== null) total = (total ?? 0) + value;
		}
		return total;
	});
}

/*
 * Only between two final figures. A month in progress compared with a finished one reads as a fall that has
 * not happened — the mistake a vendor dashboard makes when its quota emails disagree with its own page.
 */
export function changeBetween(
	to: { total: number; final: boolean } | null,
	from: { total: number; final: boolean } | null
): Change | null {
	if (!to || !from || !to.final || !from.final) return null;
	const absolute = to.total - from.total;
	return {
		absolute,
		percent:
			from.total === 0 ? null : Math.round((absolute / from.total) * 1000) / 10
	};
}

export function instanceSummary(
	rows: readonly OverviewRow[],
	monthCount: number,
	isCurrentMonth: boolean
): InstanceSummary {
	const readable = rows.filter((row) => !row.unavailable);
	const months = Array.from({ length: monthCount }, (_, index) =>
		sumMonth(rows, index)
	);
	const days = sumDays(readable.map((row) => row.days));
	const active = readable.filter((row) => (row.months[0]?.total ?? 0) > 0);
	return {
		months,
		days,
		previousDays: sumDays(readable.map((row) => row.previousDays)),
		activeBuckets: active.length,
		activeCustomers: new Set(active.map((row) => customerKey(row.customer)))
			.size,
		today: isCurrentMonth ? (days[days.length - 1] ?? null) : null,
		change: changeBetween(months[0] ?? null, months[1] ?? null)
	};
}

/* Largest first; a customer with no figure at all after every customer with one. */
export function customerSummaries(
	rows: readonly OverviewRow[],
	details: ReadonlyMap<string, CustomerDetails>
): CustomerSummary[] {
	const byCustomer = new Map<string, OverviewRow[]>();
	for (const row of rows) {
		const key = customerKey(row.customer);
		const held = byCustomer.get(key);
		if (held) held.push(row);
		else byCustomer.set(key, [row]);
	}
	const summaries = [...byCustomer.entries()].map(
		([key, held]): CustomerSummary => ({
			customer: held[0].customer,
			contacts: details.get(key)?.contacts ?? [],
			memberCount: details.get(key)?.memberCount ?? 0,
			bucketIds: held.map((row) => row.bucketId),
			current: sumMonth(held, 0),
			previous: sumMonth(held, 1)
		})
	);
	return summaries.sort(
		(a, b) =>
			(b.current?.total ?? -1) - (a.current?.total ?? -1) ||
			a.customer.label.localeCompare(b.customer.label)
	);
}

/*
 * The buckets whose figure moved sharply between two closed months: `toIndex` and the month before it.
 * Only final figures are compared, so a month in progress never raises an alarm, and a bucket with no
 * earlier figure is new rather than sharp.
 */
export function sharpChanges(
	rows: readonly OverviewRow[],
	monthLabels: readonly string[],
	toIndex: number
): SharpChanges {
	const fromIndex = toIndex + 1;
	const compared = toIndex >= 0 && fromIndex < monthLabels.length;
	const to = compared ? monthLabels[toIndex] : null;
	const from = compared ? monthLabels[fromIndex] : null;
	const changes: SharpChange[] = [];
	if (to !== null && from !== null) {
		for (const row of rows) {
			if (row.unavailable) continue;
			const later = row.months[toIndex] ?? null;
			const earlier = row.months[fromIndex] ?? null;
			if (!later || !earlier || !later.final || !earlier.final) continue;
			const absolute = later.total - earlier.total;
			if (
				Math.abs(absolute) < SHARP_CHANGE_MIN_PEOPLE ||
				Math.abs(absolute) < SHARP_CHANGE_MIN_SHARE * earlier.total
			) {
				continue;
			}
			changes.push({
				bucketId: row.bucketId,
				name: row.name,
				customer: row.customer,
				from: { period: from, total: earlier.total },
				to: { period: to, total: later.total },
				absolute,
				percent:
					earlier.total === 0
						? null
						: Math.round((absolute / earlier.total) * 1000) / 10
			});
		}
	}
	const bySize = (a: SharpChange, b: SharpChange) =>
		Math.abs(b.absolute) - Math.abs(a.absolute);
	return {
		from,
		to,
		falls: changes.filter((change) => change.absolute < 0).sort(bySize),
		rises: changes.filter((change) => change.absolute > 0).sort(bySize)
	};
}
