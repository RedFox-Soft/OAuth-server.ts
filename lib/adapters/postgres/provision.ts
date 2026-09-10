import type { SQL } from 'bun';

import {
	STORE_AREAS,
	areaForBucket,
	indexesFor,
	type IndexSpec,
	type StorageArea
} from '../../consts/storage_inventory.js';
import { columnFor, jsonPath, translateIndex } from './jsonPath.js';

/*
 * Applying the inventory to a PostgreSQL database.
 *
 * Split in two on purpose. The *plan* — every CREATE statement, as text — is a pure function of the
 * inventory, so `test/storage_contract/pg_provision_plan.spec.ts` pins all of it with no database
 * anywhere. The *appliers* below take an injected handle and do nothing but run the plan and
 * classify what came back.
 *
 * Mirrors `lib/adapters/mongodb/provision.ts`, which is already handle-injectable and import-safe for
 * the same reason, and which the operator script and the runtime bucket creation both call.
 */

/* PostgreSQL's identifier limit. Beyond it the server truncates silently, which turns two long index
 * names into one index — the reason names are hashed rather than merely cut. */
const MAX_IDENTIFIER_BYTES = 63;

/*
 * Every identifier here comes from the inventory, and the inventory's drift guard proves each field
 * name is a plain identifier. Area names are wider — a per-bucket area carries an administrator-chosen
 * bucket id — so quoting is not a formality: unquoted, PostgreSQL folds `adminAudit` to `adminaudit`
 * and the store reads a table nothing writes.
 */
function quote(identifier: string): string {
	return `"${identifier.replaceAll('"', '""')}"`;
}

/* FNV-1a, inline rather than imported: this module must stay loadable with no connection and no
 * dependency, and the hash only has to be deterministic and short, never cryptographic. */
function shortHash(value: string): string {
	let hash = 0x811c9dc5;
	for (let i = 0; i < value.length; i++) {
		hash ^= value.charCodeAt(i);
		hash = Math.imul(hash, 0x01000193) >>> 0;
	}
	return hash.toString(36).padStart(7, '0').slice(0, 7);
}

/*
 * A deterministic index name that fits.
 *
 * The readable form is `<area>_<fields>_<suffix>`. When that overflows, the name is cut and a hash of
 * the *full* logical name is appended — so two names that only differ past the cut still differ, which
 * plain truncation would not give. A long bucket id is exactly that case.
 */
export function indexName(
	area: string,
	spec: IndexSpec,
	column: string
): string {
	const suffix = spec.multikey ? 'gin' : spec.unique === true ? 'key' : 'idx';
	const fields = (spec.multikey ? [spec.multikey] : Object.keys(spec.key))
		.map((key) => nameFragment(column, key))
		.join('_');

	const full = `${area}_${fields}_${suffix}`;
	if (Buffer.byteLength(full, 'utf8') <= MAX_IDENTIFIER_BYTES) return full;

	const hash = shortHash(full);
	const room = MAX_IDENTIFIER_BYTES - hash.length - suffix.length - 2;
	return `${full.slice(0, room)}_${hash}_${suffix}`;
}

/*
 * How one declared key reads in an index name.
 *
 * A key that translates to a bare column — `expiresAt` and `_id`, the two reserved ones — is named
 * after that column rather than after the declaration, so `\d` in psql shows `expires_at` on an index
 * that really is over the `expires_at` column. Everything else keeps the declared spelling, dots
 * flattened, which is what makes `payload_grantId` recognisable back in the inventory.
 */
function nameFragment(column: string, key: string): string {
	const expression = jsonPath(column, key);
	return expression.startsWith('(') ? key.replaceAll('.', '_') : expression;
}

/*
 * The one area whose table is not the uniform three columns, and the reason is the whole point of the
 * column: `serviceConfig` holds two singleton secrets and an origin key as raw bytes, and `bytea` is
 * the only shape that hands a caller's `instanceof Uint8Array` guard something it accepts.
 *
 * The alternative — base64 inside the jsonb document — is precisely the extra encoding hop that made
 * the MongoDB store return a `Binary` where bytes were required and stopped the server booting. One
 * declared exception beats reintroducing that indirection for the sake of a uniform table.
 */
const EXTRA_COLUMNS: Readonly<Record<string, string>> = {
	[STORE_AREAS.serviceConfig]: 'secret bytea'
};

export function tableStatement(area: StorageArea): string {
	const column = columnFor(area);
	const extra = EXTRA_COLUMNS[area.name];
	return (
		`CREATE TABLE IF NOT EXISTS ${quote(area.name)} ` +
		`(id text PRIMARY KEY, ${column} jsonb NOT NULL, expires_at timestamptz` +
		`${extra ? `, ${extra}` : ''})`
	);
}

export interface PlannedIndex {
	readonly name: string;
	readonly statement: string;
}

export function indexStatements(area: StorageArea): PlannedIndex[] {
	const column = columnFor(area);

	return indexesFor(area).map((spec) => {
		const translated = translateIndex(column, spec);
		const name = indexName(area.name, spec, column);

		const unique = translated.unique ? 'UNIQUE ' : '';
		const using = translated.method === 'gin' ? 'USING gin ' : '';
		const where = translated.where ? ` WHERE ${translated.where}` : '';

		return {
			name,
			statement:
				`CREATE ${unique}INDEX IF NOT EXISTS ${quote(name)} ` +
				`ON ${quote(area.name)} ${using}(${translated.columns.join(', ')})${where}`
		};
	});
}

export interface AreaPlan {
	readonly table: string;
	readonly indexes: readonly PlannedIndex[];
}

export function planFor(area: StorageArea): AreaPlan {
	return { table: tableStatement(area), indexes: indexStatements(area) };
}

/*
 * SQLSTATE classification. Re-creating a table or an identical index is the normal case on any run
 * after the first, so neither is fatal — the same rule the MongoDB applier states for its error codes.
 */
const DUPLICATE_TABLE = '42P07';
const DUPLICATE_OBJECT = '42710';
const INSUFFICIENT_PRIVILEGE = '42501';

function sqlState(error: unknown): string | undefined {
	if (typeof error !== 'object' || error === null) return undefined;
	const code = (error as { code?: unknown }).code;
	return typeof code === 'string' ? code : undefined;
}

export function isDuplicateTable(error: unknown): boolean {
	return sqlState(error) === DUPLICATE_TABLE;
}

/*
 * An object of that name already exists. Reported rather than resolved, for the reason the MongoDB
 * applier gives: the fix would be dropping an index the inventory does not describe, and only expiry
 * rules are ours to drop — and PostgreSQL has none of those, because the sweeper replaces them.
 */
export function isIndexConflict(error: unknown): boolean {
	return sqlState(error) === DUPLICATE_OBJECT;
}

/*
 * The credentials cannot create what the inventory declares. Distinguished from every other failure
 * because it is the one an operator can act on directly, and naming it beats surfacing a raw driver
 * error that says only "permission denied".
 */
export function isInsufficientPrivilege(error: unknown): boolean {
	return sqlState(error) === INSUFFICIENT_PRIVILEGE;
}

export async function tableExists(sql: SQL, name: string): Promise<boolean> {
	/*
	 * to_regclass returns null rather than raising for an absent relation, so this is one round trip
	 * with no error handling — the direct equivalent of the MongoDB applier's listCollections check.
	 *
	 * The name is passed ALREADY QUOTED, and that is not decoration. `to_regclass` parses its argument
	 * as an identifier, so the bare string `adminAudit` is folded to `adminaudit` and reports a table
	 * that plainly exists as missing. Measured, not assumed: the first run against a real database
	 * re-created thirty-two areas it had created moments earlier, and `--check` called a healthy schema
	 * broken — the three areas it got right were the ones already spelled in lower case.
	 */
	const rows =
		await sql`SELECT to_regclass(${quote(name)}) IS NOT NULL AS present`;
	return Boolean(rows[0]?.present);
}

/*
 * Returns whether the table had to be created, so callers report only real work.
 *
 * Existence is checked explicitly rather than inferred from `IF NOT EXISTS`, which succeeds either
 * way. Trusting it would make every re-run claim it created everything — the measured defect the
 * MongoDB applier records at the same seam.
 */
export async function ensureTable(
	sql: SQL,
	area: StorageArea
): Promise<boolean> {
	if (await tableExists(sql, area.name)) return false;
	await sql.unsafe(tableStatement(area));
	return true;
}

export interface AppliedIndexes {
	readonly created: PlannedIndex[];
	readonly conflicted: PlannedIndex[];
}

/*
 * `only` narrows the set to a caller-chosen subset — used when an area's own data violates a
 * constraint, so the rest can still be applied. Defaults to everything the area declares; passing an
 * empty array applies nothing, which is the correct reading rather than a no-op to guard against.
 */
export async function applyIndexes(
	sql: SQL,
	area: StorageArea,
	only?: readonly PlannedIndex[]
): Promise<AppliedIndexes> {
	const created: PlannedIndex[] = [];
	const conflicted: PlannedIndex[] = [];

	for (const planned of only ?? indexStatements(area)) {
		try {
			await sql.unsafe(planned.statement);
			created.push(planned);
		} catch (error) {
			if (!isIndexConflict(error)) throw error;
			conflicted.push(planned);
		}
	}

	return { created, conflicted };
}

/*
 * Provision one bucket's end-user table with the constraints the inventory declares for it — today a
 * unique index on the stored (already lower-cased) email, which is what makes two concurrent
 * registrations of one address unwinnable rather than merely unlikely.
 *
 * Called when a bucket is created through the console, not only at setup time: a bucket provisioned
 * later would otherwise carry an unconstrained user table, which is precisely the hole that made the
 * duplicate-registration race reachable on the other backend.
 */
export async function provisionUserArea(
	sql: SQL,
	bucketId: string
): Promise<AppliedIndexes> {
	const area = areaForBucket(bucketId);
	await ensureTable(sql, area);
	return applyIndexes(sql, area);
}
