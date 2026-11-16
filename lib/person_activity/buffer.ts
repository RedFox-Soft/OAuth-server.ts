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

type BudgetKind = 'signInRefusals' | 'app' | 'api';

const pending = new Map<string, PersonActivityRow>();
const used: Record<BudgetKind, number> = {
	signInRefusals: 0,
	app: 0,
	api: 0
};
const usedByProject = new Map<string, number>();
let budgets: PersonActivityBudgets = PERSON_ACTIVITY_BUDGETS;

/* The id every process gives the same activity, so their writes land on one row and add up (research R9). */
export function activityId(parts: readonly string[]): string {
	return hash('sha256', JSON.stringify(parts), 'base64url');
}

function budgetKindOf(row: PersonActivityRow): BudgetKind {
	return row.kind === 'signIn' ? 'signInRefusals' : row.kind;
}

function fold(row: PersonActivityRow): void {
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
	const existing = pending.get(id);
	pending.set(id, existing ? addTo(existing, overflow) : overflow);
}

export function note(row: PersonActivityRow): void {
	const existing = pending.get(row._id);
	if (existing) {
		pending.set(row._id, addTo(existing, row));
		return;
	}
	if (row.reason !== 'signed_in') {
		const kind = budgetKindOf(row);
		const projectKey = `${row.bucketId}\u0000${kind}`;
		const byProject = usedByProject.get(projectKey) ?? 0;
		if (used[kind] >= budgets[kind] || byProject >= budgets.perProject) {
			fold(row);
			return;
		}
		used[kind] += 1;
		usedByProject.set(projectKey, byProject + 1);
	}
	pending.set(row._id, row);
}

function clearCounters(): void {
	used.signInRefusals = 0;
	used.app = 0;
	used.api = 0;
	usedByProject.clear();
}

/* Everything held, handed to the writer; the buffer starts empty and the budgets afresh. */
export function takeAll(): PersonActivityRow[] {
	const rows = [...pending.values()];
	pending.clear();
	clearCounters();
	return rows;
}

/* A deleted person's notes go with them, so a later write cannot bring them back (FR-014). */
export function dropPerson(bucketId: string, accountId: string): void {
	for (const [id, row] of pending) {
		if (row.bucketId === bucketId && row.accountId === accountId) {
			pending.delete(id);
		}
	}
}

export function dropProject(bucketId: string): void {
	for (const [id, row] of pending) {
		if (row.bucketId === bucketId) pending.delete(id);
	}
}

export function discard(): void {
	pending.clear();
	clearCounters();
}

export function resetPersonActivityForTests(): void {
	discard();
	budgets = PERSON_ACTIVITY_BUDGETS;
}

/* Lowers the bounds so a test can overflow them with a handful of notes instead of tens of thousands. */
export function setActivityBudgetsForTests(next: PersonActivityBudgets): void {
	budgets = next;
}
