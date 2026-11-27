import { getPersonActivityStore, getUserStore } from '../adapters/index.js';
import type {
	BehindProxyApp,
	PersonActivityRow,
	ProtectedResource,
	UserBucket
} from '../adapters/types.js';
import {
	REFUSALS_SCAN,
	REFUSALS_SHOWN,
	REFUSALS_WINDOW_MS
} from '../consts/person_activity.js';
import { toolWords, wordsOf } from './words.js';

/*
 * "Refused recently" on an app's or an API's Access tab (specs/134 research R6): the people refused or asked to sign in
 * again there in the last day, where the administrator who just narrowed a rule is standing (У7). Read on the project's
 * refusals index, never its use rows; a person's rows of the two UTC days the window spans fold into one line per
 * outcome, reason and rule or tool. Names only from fixed tables and what was recorded; each person by email.
 */

export interface RefusalRowView {
	accountId: string;
	email: string | null;
	outcome: 'refused' | 'sign_in_again';
	outcomeWords: string;
	reason: string;
	rule: string | null;
	tool: string | null;
	count: number;
	lastAt: string;
}

export interface RefusalsView {
	asOf: string;
	accessSavedAt: string | null;
	/* More people than shown, or more rows than one read walks: the list is the newest part. */
	cut: boolean;
	rows: RefusalRowView[];
}

export type RefusalsTarget =
	| { kind: 'app'; app: BehindProxyApp }
	| { kind: 'api'; api: ProtectedResource };

function isAt(row: PersonActivityRow, target: RefusalsTarget): boolean {
	if (target.kind === 'app') {
		return row.kind === 'app' && row.place.appId === target.app._id;
	}
	return row.kind === 'api' && row.place.resource === target.api.identifier;
}

export async function refusedRecently(
	bucket: UserBucket,
	target: RefusalsTarget,
	now = new Date()
): Promise<RefusalsView> {
	const found = await getPersonActivityStore().listRefusals(bucket._id, {
		since: new Date(now.getTime() - REFUSALS_WINDOW_MS),
		now,
		limit: REFUSALS_SCAN
	});
	const name = target.kind === 'app' ? target.app.name : target.api.name;
	const folded = new Map<string, { row: PersonActivityRow; count: number }>();
	for (const row of found) {
		if (row.outcome === 'let_in' || !isAt(row, target)) continue;
		const key = [
			row.accountId,
			row.outcome,
			row.reason,
			row.place.rule ?? '',
			row.place.tool ?? '',
			row.freshness?.requirePasskey
				? 'passkey'
				: row.freshness?.requireCode
					? 'code'
					: ''
		].join('\u0000');
		const existing = folded.get(key);
		if (existing) {
			existing.count += row.count;
			// `found` is newest first, so the first row of a key carries its latest time.
		} else {
			folded.set(key, { row, count: row.count });
		}
	}
	const lines = [...folded.values()];
	const shown = lines.slice(0, REFUSALS_SHOWN);
	const ids = [...new Set(shown.map((line) => line.row.accountId))];
	const people =
		ids.length === 0 ? [] : await getUserStore(bucket._id).findMany(ids);
	const emails = new Map(people.map((user) => [user._id, user.email]));
	const savedAt =
		target.kind === 'app' ? target.app.accessSavedAt : target.api.accessSavedAt;
	return {
		asOf: now.toISOString(),
		accessSavedAt: savedAt?.toISOString() ?? null,
		cut: lines.length > REFUSALS_SHOWN || found.length >= REFUSALS_SCAN,
		rows: shown.map(({ row, count }) => {
			const words = wordsOf(row, { place: name, client: null, provider: null });
			return {
				accountId: row.accountId,
				email: emails.get(row.accountId) ?? null,
				outcome: row.outcome === 'sign_in_again' ? 'sign_in_again' : 'refused',
				outcomeWords: words.outcome,
				reason: words.reason,
				rule: row.place.rule ?? null,
				tool: toolWords(row.place.tool),
				count,
				lastAt: row.lastAt.toISOString()
			};
		})
	};
}
