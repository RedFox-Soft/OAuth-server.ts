import { hash } from 'node:crypto';

import {
	OVERFLOW_ACCOUNT,
	PERSON_ACTIVITY_BUDGETS,
	type PersonActivityBudgets
} from '../consts/person_activity.js';
import { addTo } from '../adapters/person_activity_rows.js';
import type { PersonActivityRow } from '../adapters/types.js';

/*
 * What this process has noted and not yet written (specs/133 research R10). A note is one synchronous `Map`
 * operation that never throws and never waits, so it adds nothing a sign-in or a proxy check could notice.
 *
 * Bounded twice, because every kind of note but a successful sign-in can be repeated by an outsider: a wrong
 * password by anyone who knows an address, a refusal by anyone holding a stolen cookie. Each kind has its own
 * budget, so a flood of one never pushes out another; each project has its own quota within a kind, so one project's
 * flood never pushes out another's. A note over either bound is folded into its project's overflow row for the day,
 * a count rather than a loss. A successful sign-in is never bounded: it costs a password hash or a provider round
 * trip, and it is the one row an incident is about.
 */

type BudgetKind = 'signInRefusals' | 'app' | 'api' | 'use';

/*
 * What people used (specs/134 research R2) waits apart from everything else: it is written every five minutes rather
 * than every minute, and it has its own budget and quota, so a busy project's use never pushes out a sign-in or a
 * refusal of any project. Both maps fold into the same overflow row of a project, day and kind.
 */
const pending = new Map<string, PersonActivityRow>();
const pendingUse = new Map<string, PersonActivityRow>();
const used: Record<BudgetKind, number> = {
	signInRefusals: 0,
	app: 0,
	api: 0,
	use: 0
};
const usedByProject = new Map<string, number>();
let budgets: PersonActivityBudgets = PERSON_ACTIVITY_BUDGETS;

function isUse(row: PersonActivityRow): boolean {
	return row.reason === 'used';
}

/* The id every process gives the same activity, so their writes land on one row and add up (research R9). */
export function activityId(parts: readonly string[]): string {
	return hash('sha256', JSON.stringify(parts), 'base64url');
}

function budgetKindOf(row: PersonActivityRow): BudgetKind {
	if (isUse(row)) return 'use';
	return row.kind === 'signIn' ? 'signInRefusals' : row.kind;
}

function fold(row: PersonActivityRow): void {
	const into = isUse(row) ? pendingUse : pending;
	const id = activityId([
		row.bucketId,
		OVERFLOW_ACCOUNT,
		row.day,
		row.kind,
		'other'
	]);
	const overflow: PersonActivityRow = {
		_id: id,
		bucketId: row.bucketId,
		accountId: OVERFLOW_ACCOUNT,
		day: row.day,
		kind: row.kind,
		outcome: 'refused',
		reason: 'other',
		place: {},
		count: row.count,
		firstAt: row.firstAt,
		lastAt: row.lastAt,
		expiresAt: row.expiresAt
	};
	const existing = into.get(id);
	into.set(id, existing ? addTo(existing, overflow) : overflow);
}

export function note(row: PersonActivityRow): void {
	const into = isUse(row) ? pendingUse : pending;
	const existing = into.get(row._id);
	if (existing) {
		into.set(row._id, addTo(existing, row));
		return;
	}
	if (row.reason !== 'signed_in') {
		const kind = budgetKindOf(row);
		const projectKey = `${row.bucketId}\u0000${kind}`;
		const byProject = usedByProject.get(projectKey) ?? 0;
		const quota = kind === 'use' ? budgets.perProjectUse : budgets.perProject;
		if (used[kind] >= budgets[kind] || byProject >= quota) {
			fold(row);
			return;
		}
		used[kind] += 1;
		usedByProject.set(projectKey, byProject + 1);
	}
	into.set(row._id, row);
}

function clearCounters(use: boolean): void {
	const kinds: BudgetKind[] = use ? ['use'] : ['signInRefusals', 'app', 'api'];
	for (const kind of kinds) used[kind] = 0;
	for (const key of [...usedByProject.keys()]) {
		if (key.endsWith('\u0000use') === use) usedByProject.delete(key);
	}
}

/* Sign-ins and refusals held, handed to the minute's writer; that buffer starts empty and its budgets afresh. */
export function takeAll(): PersonActivityRow[] {
	const rows = [...pending.values()];
	pending.clear();
	clearCounters(false);
	return rows;
}

/* What people used, handed to the five-minute writer (specs/134 research R2). */
export function takeUse(): PersonActivityRow[] {
	const rows = [...pendingUse.values()];
	pendingUse.clear();
	clearCounters(true);
	return rows;
}

/* A deleted person's notes go with them, so a later write cannot bring them back (FR-014). */
export function dropPerson(bucketId: string, accountId: string): void {
	for (const map of [pending, pendingUse]) {
		for (const [id, row] of map) {
			if (row.bucketId === bucketId && row.accountId === accountId) {
				map.delete(id);
			}
		}
	}
}

export function dropProject(bucketId: string): void {
	for (const map of [pending, pendingUse]) {
		for (const [id, row] of map) {
			if (row.bucketId === bucketId) map.delete(id);
		}
	}
}

export function discard(): void {
	pending.clear();
	pendingUse.clear();
	clearCounters(false);
	clearCounters(true);
}

export function resetPersonActivityForTests(): void {
	discard();
	budgets = PERSON_ACTIVITY_BUDGETS;
}

/* Lowers the bounds so a test can overflow them with a handful of notes instead of tens of thousands. */
export function setActivityBudgetsForTests(
	next: Partial<PersonActivityBudgets>
): void {
	budgets = { ...PERSON_ACTIVITY_BUDGETS, ...next };
}
