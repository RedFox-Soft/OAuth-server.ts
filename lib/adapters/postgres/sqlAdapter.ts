import { sql } from './db.js';
import { payloadOf as decodePayload } from './json.js';
import type { ModelAdapter } from '../types.js';
import type { PayloadForModel } from '../modelTypes.js';

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
> implements ModelAdapter<PayloadForModel<TModelName>> {
	name: TModelName;

	constructor(name: TModelName) {
		this.name = name;
	}

	async upsert(
		_id: string,
		payload: PayloadForModel<TModelName>,
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
	async find(_id: string): Promise<PayloadForModel<TModelName> | undefined> {
		const handle = sql();
		const rows = await handle`
			SELECT payload FROM ${handle(this.name)} WHERE id = ${_id}
		`;
		return this.payloadOf(rows[0]);
	}

	async findByUserCode(
		userCode: string
	): Promise<PayloadForModel<TModelName> | undefined> {
		const handle = sql();
		const rows = await handle`
			SELECT payload FROM ${handle(this.name)}
			WHERE payload->>'userCode' = ${userCode}
		`;
		return this.payloadOf(rows[0]);
	}

	async findByUid(
		uid: string
	): Promise<PayloadForModel<TModelName> | undefined> {
		const handle = sql();
		const rows = await handle`
			SELECT payload FROM ${handle(this.name)} WHERE payload->>'uid' = ${uid}
		`;
		return this.payloadOf(rows[0]);
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

	async consume(_id: string): Promise<void> {
		const handle = sql();
		const consumedAt = Math.floor(Date.now() / 1000);
		await handle`
			UPDATE ${handle(this.name)}
			SET payload = jsonb_set(payload, '{consumed}', to_jsonb(${consumedAt}::bigint))
			WHERE id = ${_id}
		`;
	}

	/*
	 * A jsonb column arrives already decoded, so this claims only that the decoded value is the payload
	 * the model wrote. No runtime check can establish more: the payload's shape is the model's TypeBox
	 * schema, which is deliberately not this layer's business — the storage contract's rule is that a
	 * payload round-trips unchanged, not that the adapter understands it.
	 */
	private payloadOf(row: unknown): PayloadForModel<TModelName> | undefined {
		return decodePayload<PayloadForModel<TModelName>>(row);
	}
}
