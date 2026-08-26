import { errorStore } from '../../adapters/index.js';
import type { ErrorStoreQuery } from '../../adapters/types.js';
import nanoid from '../../helpers/nanoid.js';
import { AdminError, type AdminContext } from '../auth/rbac.js';
import { recordAdminAudit } from '../audit/record.js';

/*
 * Whether a query actually narrows anything.
 *
 * Paging is not a filter: `?limit=10` selects a page of everything, so a purge carrying only paging
 * would destroy the whole store while looking scoped. Checked on the resolved query rather than the raw
 * URL so an empty-string parameter — which the parser drops — cannot pass as a filter either.
 */
const FILTERING_KEYS: readonly (keyof ErrorStoreQuery)[] = [
	'errorCode',
	'route',
	'surface',
	'status',
	'clientId',
	'actor',
	'reference',
	'from',
	'to'
];

export function filterKeysOf(query: ErrorStoreQuery): string[] {
	return FILTERING_KEYS.filter((key) => query[key] !== undefined).sort();
}

export interface PurgeOutcome {
	removed: number;
	/* Ties the two audit entries together, and is what a reviewer searches the trail by. */
	purgeId: string;
}

/*
 * Purges recorded faults, audit-first.
 *
 * The audit entry precedes the deletion, so a trail that refuses a write aborts the request and nothing
 * is destroyed — the same ordering, for the same reason, as every other mutating admin operation. The
 * cost of the alternative is specific: delete-then-record means a trail failure loses the only account
 * of what happened, on the one operation whose effects cannot be inspected afterwards.
 *
 * That ordering has a visible consequence. The first entry can only state an intention — it is written
 * before the count is known — so the outcome is a *second* entry under the same action. Two records
 * rather than one amended record, because the trail has no update path by construction.
 */
export async function purgeErrors(
	ctx: AdminContext,
	query: ErrorStoreQuery
): Promise<PurgeOutcome> {
	const filters = filterKeysOf(query);
	if (filters.length === 0) {
		/*
		 * Refused rather than treated as "purge everything". An empty filter is far more often a caller's
		 * bug than an intention, and the cost of guessing wrong is the entire store.
		 */
		throw new AdminError(
			422,
			'a purge must carry at least one filter; refusing to purge every record'
		);
	}

	const purgeId = `purge:${nanoid()}`;

	/*
	 * No preview is taken here, deliberately. It would be a second query whose number could not go
	 * anywhere useful: the entry below is written *before* the deletion, so it can only state an
	 * intention, and the actual count arrives with the outcome entry. An operator who wants to know
	 * beforehand asks the preview endpoint, which is what it is for.
	 */
	await recordAdminAudit(ctx, 'error.purge', purgeId, {
		/*
		 * Field NAMES, never their values — the trail's standing rule, and it holds here even though a
		 * filter value is rarely secret: a `clientId` or an `actor` email would put a principal's
		 * identifier into a record about somebody else's action.
		 */
		attributes: filters
	});

	const removed = await errorStore.purge(query);

	/*
	 * The outcome, as its own entry. `removed=<n>` is a count rather than a field name, which stretches
	 * `attributes` past its usual meaning — accepted deliberately: a count is not a secret, and the
	 * alternative was either a schema change to an append-only store or a trail that never says what a
	 * purge actually destroyed.
	 */
	await recordAdminAudit(ctx, 'error.purge', purgeId, {
		attributes: [...filters, `removed=${removed}`]
	});

	return { removed, purgeId };
}
