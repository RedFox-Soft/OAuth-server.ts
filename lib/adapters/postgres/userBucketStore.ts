import { sql } from './db.js';
import { docOf } from './json.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { provisionUserArea } from './provision.js';
import { reviveDates } from './dates.js';
import type { UserBucket, UserBucketStoreInstance } from '../types.js';
import type { FederationProvider } from '../../federation/types.js';
import nanoid from '../../helpers/nanoid.js';

const DATE_FIELDS = ['createdAt', 'updatedAt'] as const;

/*
 * Buckets written before a setting existed hold no value for it, so the safe default is projected on
 * read and callers always see the full shape.
 *
 * Two of these are not conveniences. `passwordLogin` is read as a boolean and undefined is falsy, so
 * leaving it out would close the password door on every bucket that predates federation; `totpRequired`
 * is its mirror. Carried over to this backend unchanged even though no PostgreSQL deployment can hold
 * a document that old — two stores answering differently for the same input is a divergence with
 * nothing to gain.
 */
function withDefaults(bucket: UserBucket | null): UserBucket | null {
	if (!bucket) return null;
	return {
		...bucket,
		registrationOpen: bucket.registrationOpen ?? true,
		emailVerificationRequired: bucket.emailVerificationRequired ?? false,
		verificationMethod: bucket.verificationMethod ?? 'link',
		passwordLogin: bucket.passwordLogin ?? true,
		federation: bucket.federation ?? [],
		totpRequired: bucket.totpRequired ?? false
	};
}

export class UserBucketStore implements UserBucketStoreInstance {
	private area: string = STORE_AREAS.userBuckets;

	async create(data: {
		_id?: string;
		name: string;
		ownerGroupId: string;
		roles?: string[];
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
			ownerGroupId: data.ownerGroupId,
			roles: data.roles ?? [],
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
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${bucket._id}, ${bucket}, NULL)
		`;

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
				| 'roles'
				| 'passwordLogin'
				| 'federation'
				| 'registrationOpen'
				| 'emailVerificationRequired'
				| 'verificationMethod'
				| 'totpRequired'
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

	async destroy(id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${id}`;
	}

	private bucketOf(row: unknown): UserBucket | null {
		const doc = docOf<UserBucket>(row);
		return doc === undefined
			? null
			: withDefaults(reviveDates(doc, DATE_FIELDS));
	}

	private bucketsOf(rows: unknown[]): UserBucket[] {
		return rows
			.map((row) => this.bucketOf(row))
			.filter((bucket): bucket is UserBucket => bucket !== null);
	}
}
