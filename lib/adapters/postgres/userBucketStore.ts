import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { provisionUserArea } from './provision.js';
import { documentOf } from '../documents.js';
import {
	UserBucket,
	type BucketDeletion,
	type UserBucketStoreInstance
} from '../types.js';
import type { FederationProvider } from '../../federation/types.js';
import { UniqueValueTaken } from '../conflicts.js';
import { isUniqueViolation } from './sqlState.js';
import { isRecord } from '../../helpers/_/object.js';
import nanoid from '../../helpers/nanoid.js';

/*
 * Buckets written before a setting existed hold no value for it, so the safe default is projected on
 * read and callers always see the full shape.
 *
 * Two of these are not conveniences. `passwordLogin` is read as a boolean and undefined is falsy, so
 * leaving it out would close the password door on every bucket that predates federation; `totpRequired`
 * is its mirror. Carried over to this backend unchanged even though no PostgreSQL deployment can hold
 * a document that old — two stores answering differently for the same input is a divergence with
 * nothing to gain. Applied before the schema check, which would otherwise refuse such a document.
 */
function withDefaults(doc: unknown): unknown {
	if (!isRecord(doc)) return doc;
	return {
		...doc,
		registrationOpen: doc.registrationOpen ?? true,
		emailVerificationRequired: doc.emailVerificationRequired ?? false,
		verificationMethod: doc.verificationMethod ?? 'link',
		passwordLogin: doc.passwordLogin ?? true,
		federation: doc.federation ?? [],
		totpRequired: doc.totpRequired ?? false
	};
}

export class UserBucketStore implements UserBucketStoreInstance {
	private area: string = STORE_AREAS.userBuckets;

	async create(data: {
		_id?: string;
		name: string;
		slug?: string;
		host?: string;
		ownerGroupId: string;
		passwordLogin?: boolean;
		federation?: FederationProvider[];
		registrationOpen?: boolean;
		emailVerificationRequired?: boolean;
		verificationMethod?: UserBucket['verificationMethod'];
		totpRequired?: boolean;
	}): Promise<UserBucket> {
		const now = new Date();
		const bucket: UserBucket = {
			_id: data._id ?? nanoid(),
			name: data.name,
			slug: data.slug,
			/* Written only when present: a stored null would occupy the partial unique index, so the
			 * second bucket created without a hostname would collide with the first. */
			...(data.host !== undefined ? { host: data.host } : {}),
			ownerGroupId: data.ownerGroupId,
			passwordLogin: data.passwordLogin ?? true,
			federation: data.federation ?? [],
			registrationOpen: data.registrationOpen ?? true,
			emailVerificationRequired: data.emailVerificationRequired ?? false,
			verificationMethod: data.verificationMethod ?? 'link',
			totpRequired: data.totpRequired ?? false,
			createdAt: now,
			updatedAt: now
		};

		const handle = sql();
		try {
			await handle`
				INSERT INTO ${handle(this.area)} (id, doc, expires_at)
				VALUES (${bucket._id}, ${bucket}, NULL)
			`;
		} catch (error) {
			if (data.host !== undefined && isUniqueViolation(error)) {
				throw new UniqueValueTaken('host', data.host);
			}
			throw error;
		}

		/*
		 * Provision the bucket's end-user table now, while we know the bucket is new. Buckets are created
		 * at runtime through the admin control plane, so leaving this to the operator routine would mean
		 * every bucket created after deployment held its accounts in an unconstrained table — no unique
		 * email index, and therefore a registration race that can produce two accounts on one address.
		 *
		 * This is the runtime DDL the plan calls out as the cost of keeping a bucket's users an *area* on
		 * both backends rather than a row filter on one of them.
		 */
		await provisionUserArea(handle, bucket._id);
		return bucket;
	}

	async find(id: string): Promise<UserBucket | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${id}
		`;
		return this.bucketOf(rows[0]);
	}

	async findBySlug(slug: string): Promise<UserBucket | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE doc->>'slug' = ${slug}
		`;
		return this.bucketOf(rows[0]);
	}

	/*
	 * Matched exactly, never normalised here — a store that folded case on read would answer a lookup the
	 * unique index never saw. Normalisation is done at the edges, by lib/consts/request_host.ts, so what
	 * is compared is what is stored.
	 */
	async findByHost(host: string): Promise<UserBucket | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE doc->>'host' = ${host}
		`;
		return this.bucketOf(rows[0]);
	}

	async setAddress(
		id: string,
		address: { slug?: string; host?: string }
	): Promise<UserBucket | null> {
		const handle = sql();
		/*
		 * Merge one form, then drop the other: a bucket holds one address, never both. `-` removes the
		 * key outright rather than setting it null, which matters because a null would occupy the partial
		 * unique index rather than being excluded from it. Arrivals at the old address say nothing about
		 * the new one, so they are dropped in the same write.
		 */
		const dropped = [
			address.host === undefined ? 'host' : 'slug',
			'hostFirstSeenAt',
			'hostLastSeenAt'
		];
		const merged = { ...address, updatedAt: new Date() };
		try {
			const rows = await handle`
				UPDATE ${handle(this.area)}
				SET doc = (doc || ${merged}) - ${handle.array(dropped, 'text')}
				WHERE id = ${id}
				RETURNING doc
			`;
			return this.bucketOf(rows[0]);
		} catch (error) {
			if (address.host !== undefined && isUniqueViolation(error)) {
				throw new UniqueValueTaken('host', address.host);
			}
			throw error;
		}
	}

	async list(): Promise<UserBucket[]> {
		const handle = sql();
		const rows = await handle`SELECT doc FROM ${handle(this.area)}`;
		return this.bucketsOf(rows);
	}

	async listByGroup(groupId: string): Promise<UserBucket[]> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE doc->>'ownerGroupId' = ${groupId}
		`;
		return this.bucketsOf(rows);
	}

	async update(
		id: string,
		patch: Partial<
			Pick<
				UserBucket,
				| 'name'
				| 'ownerGroupId'
				| 'passwordLogin'
				| 'federation'
				| 'registrationOpen'
				| 'emailVerificationRequired'
				| 'verificationMethod'
				| 'totpRequired'
				| 'hostFirstSeenAt'
				| 'hostLastSeenAt'
				| 'signInOrder'
			>
		>
	): Promise<UserBucket | null> {
		const handle = sql();
		const merged = { ...patch, updatedAt: new Date() };
		const rows = await handle`
			UPDATE ${handle(this.area)} SET doc = doc || ${merged}
			WHERE id = ${id}
			RETURNING doc
		`;
		return this.bucketOf(rows[0]);
	}

	async repairReservedSlug(id: string, slug: string): Promise<void> {
		const handle = sql();
		/*
		 * `jsonb_set` merges server-side rather than reading, mutating and writing the document back: a
		 * round trip is where a document gets re-serialised.
		 *
		 * The value goes in as text and becomes jsonb in the database (`to_jsonb`). Bun's client JSON-encodes
		 * a string bound to a `::jsonb` cast, so the earlier `${JSON.stringify(slug)}::jsonb` stored the slug
		 * with its quotes — `"\"default\""` — and `findBySlug` could no longer find the bucket. A record that
		 * write already damaged holds exactly `JSON.stringify(slug)`, so it is repaired too: that value is
		 * never a slug anyone chose (a slug cannot contain a quote), so this still never renames a bucket.
		 */
		await handle`
			UPDATE ${handle(this.area)}
			SET doc = jsonb_set(doc, '{slug}', to_jsonb(${slug}::text))
			WHERE id = ${id}
				AND (doc->>'slug' IS NULL OR doc->>'slug' = ${JSON.stringify(slug)})
		`;
	}

	/*
	 * Each transition is one `UPDATE … WHERE <condition> RETURNING`, so the database decides the race.
	 *
	 * Values go in as objects (`doc || ${…}`) or as text made jsonb in the database (`to_jsonb`), never as
	 * `JSON.stringify(...)` — the trap `repairReservedSlug` above records. Dates are compared as
	 * `timestamptz`: a document stores them as the ISO text `JSON.stringify` writes, and the bound side is
	 * the same text cast the same way, so neither depends on the driver's encoding of a Date.
	 */
	async scheduleDeletion(
		id: string,
		deletion: Omit<BucketDeletion, 'purge'>
	): Promise<UserBucket | null> {
		const handle = sql();
		const merged = { deletion, updatedAt: new Date() };
		const rows = await handle`
			UPDATE ${handle(this.area)} SET doc = doc || ${merged}
			WHERE id = ${id} AND doc->'deletion' IS NULL
			RETURNING doc
		`;
		return this.bucketOf(rows[0]);
	}

	async cancelDeletion(id: string, now: Date): Promise<UserBucket | null> {
		const handle = sql();
		const merged = { updatedAt: new Date() };
		const rows = await handle`
			UPDATE ${handle(this.area)} SET doc = (doc - 'deletion') || ${merged}
			WHERE id = ${id}
				AND doc->'deletion' IS NOT NULL
				AND NOT COALESCE(
					(doc #>> '{deletion,purge,claimedUntil}')::timestamptz >= ${now.toISOString()}::timestamptz,
					false
				)
			RETURNING doc
		`;
		return this.bucketOf(rows[0]);
	}

	async claimPurge(
		id: string,
		now: Date,
		until: Date,
		options: { due: boolean }
	): Promise<UserBucket | null> {
		const handle = sql();
		const at = now.toISOString();
		const claim = { claimedUntil: until };
		/* Merged into what is there, so `recordedAt` survives the claim and a retry never records twice. */
		const rows = await handle`
			UPDATE ${handle(this.area)}
			SET doc = jsonb_set(
				doc,
				'{deletion,purge}',
				COALESCE(doc #> '{deletion,purge}', '{}'::jsonb) || ${claim}
			)
			WHERE id = ${id}
				AND doc->'deletion' IS NOT NULL
				AND NOT COALESCE(
					(doc #>> '{deletion,purge,claimedUntil}')::timestamptz >= ${at}::timestamptz,
					false
				)
				AND (
					${!options.due}
					OR (doc #>> '{deletion,purgeAt}')::timestamptz <= ${at}::timestamptz
				)
			RETURNING doc
		`;
		return this.bucketOf(rows[0]);
	}

	async markPurgeRecorded(id: string, at: Date): Promise<void> {
		const handle = sql();
		await handle`
			UPDATE ${handle(this.area)}
			SET doc = jsonb_set(
				doc,
				'{deletion,purge,recordedAt}',
				to_jsonb(${at.toISOString()}::text)
			)
			WHERE id = ${id} AND doc #> '{deletion,purge}' IS NOT NULL
		`;
	}

	async destroy(id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${id}`;
	}

	private bucketOf(row: unknown): UserBucket | null {
		const doc = docOf(row);
		return doc === undefined
			? null
			: documentOf(this.area, UserBucket, withDefaults(doc));
	}

	private bucketsOf(rows: unknown[]): UserBucket[] {
		return rows
			.map((row) => this.bucketOf(row))
			.filter((bucket): bucket is UserBucket => bucket !== null);
	}
}
