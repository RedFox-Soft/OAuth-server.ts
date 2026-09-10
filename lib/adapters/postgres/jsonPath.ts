import type { IndexSpec, StorageArea } from '../../consts/storage_inventory.js';

/*
 * Translating a declared MongoDB index into a PostgreSQL one.
 *
 * Pure functions over plain descriptors, and deliberately so: this module imports no driver and opens
 * no connection, which is what lets test/storage_contract/json_path.spec.ts pin every row of the
 * translation without a database. Same arrangement, for the same reason, as database/reconcile.ts.
 *
 * The failure mode this guards is quiet. A wrong expression does not error — it builds an index the
 * planner never chooses, and the lookup degrades to a sequential scan that only shows up as a slow
 * query under load.
 */

export type IndexMethod = 'btree' | 'gin';

export interface TranslatedIndex {
	readonly method: IndexMethod;
	/* Index expressions in declared order. Order is the whole value of a composite index. */
	readonly columns: readonly string[];
	readonly unique: boolean;
	/* A partial-index predicate, present only for the expiry index. */
	readonly where?: string;
}

/*
 * The two declared key names that are real columns rather than JSON fields.
 *
 * `expiresAt` is a column because the sweeper and its partial index need it typed as a timestamp;
 * `_id` is one because it is the primary key. Everything else lives inside the document column, so
 * these two are the whole special case — enumerated here rather than tested for at each call site.
 */
const RESERVED: Readonly<Record<string, string>> = {
	expiresAt: 'expires_at',
	_id: 'id'
};

/*
 * A plain identifier: what the inventory's own drift guard already proves every declared field name
 * to be. Checked again here anyway, because that guarantee lives in another file and this is the
 * point where a field name becomes SQL text. A translation that merely trusted it would be one
 * careless refactor away from an injection, and the check costs nothing.
 */
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

function segment(name: string): string {
	if (!IDENTIFIER.test(name)) {
		throw new Error(
			`'${name}' is not a plain identifier and cannot be used in an index expression`
		);
	}
	return `'${name}'`;
}

/* Which column an area keeps its document in. Model areas name it in their declared keys already
 * (`payload.grantId`), which is what lets jsonPath drop the prefix instead of nesting under it. */
export function columnFor(area: Pick<StorageArea, 'kind'>): string {
	return area.kind === 'model' ? 'payload' : 'doc';
}

/*
 * One declared key to one PostgreSQL expression.
 *
 * `->` walks, `->>` extracts as text; the leaf uses `->>` so comparisons are against text rather than
 * jsonb, matching how every one of these fields is queried.
 */
export function jsonPath(column: string, key: string): string {
	const reserved = RESERVED[key];
	if (reserved) return reserved;

	const parts = key.split('.');
	/* A model area's keys are prefixed with the column they live in; drop it rather than nest. */
	if (parts.length > 1 && parts[0] === column) parts.shift();

	const leaf = parts.pop();
	if (leaf === undefined) {
		throw new Error('an index key cannot be empty');
	}

	const walk = parts.map((part) => `->${segment(part)}`).join('');
	return `(${column}${walk}->>${segment(leaf)})`;
}

/*
 * One declared index to one PostgreSQL index.
 *
 * Three shapes come out of here and the differences are load-bearing:
 *
 *   - a multikey key becomes a GIN index over the ARRAY CONTAINER, not the leaf. MongoDB indexes array
 *     members automatically; PostgreSQL needs to be told, and a b-tree over an array value indexes the
 *     whole array as one text value and matches nothing.
 *   - an expiry index becomes partial. Two areas hold expiring and permanent records side by side by
 *     design, and the sweeper only ever scans rows that can expire.
 *   - everything else is a b-tree over the expressions, in declared order.
 */
export function translateIndex(
	column: string,
	spec: IndexSpec
): TranslatedIndex {
	const keys = Object.keys(spec.key);

	if (spec.multikey) {
		return {
			method: 'gin',
			columns: [`(${column}->${segment(spec.multikey)})`],
			/* A GIN index cannot be unique, and no multikey declaration asks to be. */
			unique: false
		};
	}

	const columns = keys.map((key) => jsonPath(column, key));
	const unique = spec.unique === true;

	if (spec.expireAfterSeconds !== undefined) {
		return {
			method: 'btree',
			columns,
			unique,
			where: `${RESERVED.expiresAt} IS NOT NULL`
		};
	}

	return { method: 'btree', columns, unique };
}
