import { sql } from './db.js';
import { payloadOf } from './json.js';
import type { ModelAdapter } from '../types.js';

type StoredRecord = Record<string, unknown>;

/*
 * The model adapter over PostgreSQL.
 *
 * Every model area is one table of the same three columns — `(id text, payload jsonb, expires_at
 * timestamptz)` — which is the MongoDB document `{ _id, payload, expiresAt }` columnised. Mirroring
 * the document model rather than relationalising it is what keeps `lib/consts/storage_inventory.ts`
 * the single declaration of what exists: the alternative is a second, partial copy of every model's
 * TypeBox schema living in DDL, kept in step by review.
 *
 * `sql()` is called per method rather than held, because the handle is built lazily on first use —
 * that laziness is what keeps this module importable with no PostgreSQL anywhere, which the mongodb
 * adapter's eager connection does not allow. Table names go through `handle(name)`, which quotes
 * them; they come from the inventory and never from a caller, the same guarantee the MongoDB adapter
 * states at its two interpolation sites.
 */
export class SqlAdapter<
	TModelName extends string = string
> implements ModelAdapter<StoredRecord> {
	name: TModelName;

	constructor(name: TModelName) {
		this.name = name;
	}

	async upsert(
		_id: string,
		payload: StoredRecord,
		expiresIn?: number
	): Promise<void> {
		const handle = sql();
		const expiresAt = expiresIn
			? new Date(Date.now() + expiresIn * 1000)
			: null;

		/*
		 * The payload replaces wholesale rather than merging: the model's shallow projection IS the
		 * record, so a merge would resurrect a field the writer deliberately dropped.
		 *
		 * `expires_at` is written unconditionally, which clears a stored expiry when no ttl is given —
		 * the natural ON CONFLICT write, and where this backend differs from MongoDB, whose `$set`
		 * leaves a stale value behind. That difference is declared rather than converged because it is
		 * unobservable: a reaped area receives a ttl on every upsert, and `Client`, the one area
		 * upserted without one, has no expiry index for a stale value to feed.
		 * `test/storage_contract/ttl_pairing.spec.ts` is what keeps that true.
		 */
		await handle`
			INSERT INTO ${handle(this.name)} (id, payload, expires_at)
			VALUES (${_id}, ${payload}, ${expiresAt})
			ON CONFLICT (id) DO UPDATE
			SET payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at
		`;
	}

	/*
	 * No expiry filter, deliberately. `MongoAdapter.find` does not filter either — expiry is enforced
	 * one layer up in the model's `tryFind`, and the datastore's reaping only reclaims space, on its
	 * own schedule. Filtering here would make the two adapters disagree about what they return in the
	 * window between expiry and reaping, which is a divergence dressed as a fix.
	 */
	async find(_id: string): Promise<StoredRecord | undefined> {
		const handle = sql();
		const rows = await handle`
			SELECT payload FROM ${handle(this.name)} WHERE id = ${_id}
		`;
		return payloadOf(rows[0]);
	}

	async findByUserCode(userCode: string): Promise<StoredRecord | undefined> {
		const handle = sql();
		const rows = await handle`
			SELECT payload FROM ${handle(this.name)}
			WHERE payload->>'userCode' = ${userCode}
		`;
		return payloadOf(rows[0]);
	}

	async findByUid(uid: string): Promise<StoredRecord | undefined> {
		const handle = sql();
		const rows = await handle`
			SELECT payload FROM ${handle(this.name)} WHERE payload->>'uid' = ${uid}
		`;
		return payloadOf(rows[0]);
	}

	async destroy(_id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.name)} WHERE id = ${_id}`;
	}

	async revokeByGrantId(grantId: string): Promise<void> {
		const handle = sql();
		await handle`
			DELETE FROM ${handle(this.name)} WHERE payload->>'grantId' = ${grantId}
		`;
	}

	/*
	 * The one way to reach a principal's records. Nothing else can enumerate by owner, and a grant walk
	 * misses ClientCredentials (no grantId) and RegistrationAccessToken (no expiry) entirely.
	 *
	 * `field` is a declared inventory value, never caller input, and the inventory's drift guard proves
	 * each one is a plain identifier — which is what lets it be a bound parameter to `->>` here, as it
	 * is safe interpolated into a filter on the other backend.
	 */
	/* `field` is a declared inventory value bound as a parameter, exactly as in `destroyByOwner`. */
	async findByOwner(field: string, value: string): Promise<StoredRecord[]> {
		const handle = sql();
		const rows = await handle`
			SELECT payload FROM ${handle(this.name)}
			WHERE payload->>${field} = ${value}
		`;
		return rows
			.map((row: unknown) => payloadOf(row))
			.filter(
				(payload: StoredRecord | undefined): payload is StoredRecord =>
					payload !== undefined
			);
	}

	async destroyByOwner(field: string, value: string): Promise<number> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.name)}
			WHERE payload->>${field} = ${value}
			RETURNING id
		`;
		return rows.length;
	}

	/*
	 * Records that were written and never taken up. A different question from `destroyByOwner`'s, and
	 * the reason it is a second method: not "which records belong to this principal" but "which were
	 * never used".
	 *
	 * The absence test is `payload->key IS NULL`, which is key absence and not falsiness — matching
	 * `$exists: false` on the other backend. It reads as the weaker test and is not: a key present with
	 * a JSON null yields jsonb `null`, which is not SQL NULL, so only a genuinely missing key matches.
	 * Written this way rather than with the `?` containment operator, whose bare question mark is the
	 * one piece of jsonb syntax that placeholder-rewriting layers are known to eat.
	 */
	async destroyUnusedSince(
		markerField: string,
		usedField: string,
		ageField: string,
		before: number
	): Promise<number> {
		const handle = sql();
		const rows = await handle`
			DELETE FROM ${handle(this.name)}
			WHERE payload->>${markerField} = 'true'
			  AND payload->${usedField} IS NULL
			  AND (payload->>${ageField})::numeric < ${before}
			RETURNING id
		`;
		return rows.length;
	}

	/*
	 * The unconsumed state is part of the WHERE, so of racing callers only one updates the row; the
	 * others find nothing to update and are told so. An absent key is a record written before `consumed`
	 * defaulted to `false`.
	 */
	async consume(_id: string): Promise<boolean> {
		const handle = sql();
		const consumedAt = Math.floor(Date.now() / 1000);
		const rows = await handle`
			UPDATE ${handle(this.name)}
			SET payload = jsonb_set(payload, '{consumed}', to_jsonb(${consumedAt}::bigint))
			WHERE id = ${_id}
			AND (payload->'consumed' IS NULL OR payload->'consumed' = 'false'::jsonb)
			RETURNING id
		`;
		return rows.length === 1;
	}

	/*
	 * One UPDATE answering the value it wrote, so racing callers each read back their own. `field` is a
	 * code constant and travels as a bound parameter in both the path and the read, never as SQL text.
	 */
	async increment(
		_id: string,
		field: string,
		expiresIn?: number
	): Promise<number | undefined> {
		const handle = sql();
		// `handle.array`: Bun binds a bare JS array as text PostgreSQL cannot read as an array.
		const counted = handle`
			jsonb_set(
				payload,
				${handle.array([field], 'text')},
				to_jsonb(COALESCE((payload->>${field})::numeric, 0) + 1)
			)
		`;
		const rows =
			expiresIn === undefined
				? await handle<{ value: unknown }[]>`
						UPDATE ${handle(this.name)}
						SET payload = ${counted}
						WHERE id = ${_id}
						RETURNING (payload->>${field})::float8 AS value
					`
				: await handle<{ value: unknown }[]>`
						UPDATE ${handle(this.name)}
						SET payload = jsonb_set(
								${counted},
								'{exp}',
								to_jsonb(${Math.floor(Date.now() / 1000) + expiresIn}::bigint)
							),
							expires_at = ${new Date(Date.now() + expiresIn * 1000)}
						WHERE id = ${_id}
						RETURNING (payload->>${field})::float8 AS value
					`;
		const value: unknown = rows[0]?.value;
		return typeof value === 'number' ? value : undefined;
	}

	/*
	 * Inserts, or replaces a row whose expiry has passed but which the sweeper has not reaped yet; a live
	 * row is left alone and nothing is returned for it. One statement, so the primary key decides a race.
	 */
	async create(
		_id: string,
		payload: StoredRecord,
		expiresIn: number
	): Promise<boolean> {
		const handle = sql();
		const expiresAt = new Date(Date.now() + expiresIn * 1000);
		const table = handle(this.name);
		const rows = await handle`
			INSERT INTO ${table} (id, payload, expires_at)
			VALUES (${_id}, ${payload}, ${expiresAt})
			ON CONFLICT (id) DO UPDATE
			SET payload = EXCLUDED.payload, expires_at = EXCLUDED.expires_at
			WHERE ${table}.expires_at IS NOT NULL AND ${table}.expires_at <= now()
			RETURNING id
		`;
		return rows.length === 1;
	}
}
