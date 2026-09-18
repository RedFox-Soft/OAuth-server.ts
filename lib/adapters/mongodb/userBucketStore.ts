import { db } from './db.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { provisionUserArea } from './provision.js';
import type { UserBucket, UserBucketStoreInstance } from '../types.js';
import type { FederationProvider } from '../../federation/types.js';
import { UniqueValueTaken } from '../conflicts.js';
import nanoid from '../../helpers/nanoid.js';

/* The driver's duplicate-key code, classified here exactly as migrationLeaseStore classifies it. */
function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'code' in error &&
		(error as { code: unknown }).code === 11000
	);
}

// Buckets created before the verification settings existed have no stored values;
// project the safe defaults on read so callers always see the full shape.
function withDefaults(bucket: UserBucket | null): UserBucket | null {
	if (!bucket) return null;
	return {
		...bucket,
		registrationOpen: bucket.registrationOpen ?? true,
		emailVerificationRequired: bucket.emailVerificationRequired ?? false,
		verificationMethod: bucket.verificationMethod ?? 'link',
		// Every bucket written before federation existed accepted passwords and held no providers, and
		// must keep doing so. `passwordLogin` in particular cannot be left undefined: it is read as a
		// boolean, and undefined is falsy, which would close the password door on every existing bucket.
		passwordLogin: bucket.passwordLogin ?? true,
		federation: bucket.federation ?? [],
		// Undefined is falsy, and "not required" is the right reading for a bucket written before the
		// second factor existed — the mirror of the passwordLogin default above.
		totpRequired: bucket.totpRequired ?? false
	};
}

export class UserBucketStore implements UserBucketStoreInstance {
	private collection = db.collection<UserBucket>(STORE_AREAS.userBuckets);

	async create(data: {
		_id?: string;
		name: string;
		slug?: string;
		host?: string;
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
			slug: data.slug,
			/*
			 * Written only when present, never as an explicit undefined. A stored null would occupy the
			 * unique sparse index, so the second bucket created without a hostname would collide with the
			 * first — the failure the index is sparse to avoid.
			 */
			...(data.host !== undefined ? { host: data.host } : {}),
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
		try {
			await this.collection.insertOne(bucket);
		} catch (error) {
			if (data.host !== undefined && isDuplicateKey(error)) {
				throw new UniqueValueTaken('host', data.host);
			}
			throw error;
		}
		/*
		 * Provision the bucket's end-user collection now, while we know the bucket is new. Buckets are
		 * created at runtime through the admin control plane, so leaving this to the operator routine
		 * would mean every bucket created after deployment held its accounts in an unconstrained
		 * collection — no unique email index, and therefore a registration race that can produce two
		 * accounts on one address.
		 */
		await provisionUserArea(db, bucket._id);
		return bucket;
	}

	async find(id: string): Promise<UserBucket | null> {
		return withDefaults(await this.collection.findOne({ _id: id }));
	}

	async findBySlug(slug: string): Promise<UserBucket | null> {
		return withDefaults(await this.collection.findOne({ slug }));
	}

	/*
	 * Matched exactly, never normalised here — a store that folded case on read would answer a lookup the
	 * unique index never saw, so two names differing only in case could both be stored and one would
	 * resolve to the other's bucket. Normalisation is done at the edges, by lib/consts/request_host.ts,
	 * so what is compared is what is stored.
	 */
	async findByHost(host: string): Promise<UserBucket | null> {
		return withDefaults(await this.collection.findOne({ host }));
	}

	async setAddress(
		id: string,
		address: { slug?: string; host?: string }
	): Promise<UserBucket | null> {
		/* One form set, the other unset in the same update: a bucket holds one address, never both. An
		 * absent hostname must be *removed* rather than written null, or it would occupy the unique
		 * sparse index and collide with every other bucket that has none. */
		const unset = address.host === undefined ? { host: '' } : { slug: '' };
		try {
			return withDefaults(
				await this.collection.findOneAndUpdate(
					{ _id: id },
					{ $set: { ...address, updatedAt: new Date() }, $unset: unset },
					{ returnDocument: 'after' }
				)
			);
		} catch (error) {
			if (address.host !== undefined && isDuplicateKey(error)) {
				throw new UniqueValueTaken('host', address.host);
			}
			throw error;
		}
	}

	async list(): Promise<UserBucket[]> {
		return (await this.collection.find().toArray()).map(
			(b) => withDefaults(b) as UserBucket
		);
	}

	async listByGroup(groupId: string): Promise<UserBucket[]> {
		return (
			await this.collection.find({ ownerGroupId: groupId }).toArray()
		).map((b) => withDefaults(b) as UserBucket);
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
				| 'hostFirstSeenAt'
				| 'hostLastSeenAt'
			>
		>
	): Promise<UserBucket | null> {
		return withDefaults(
			await this.collection.findOneAndUpdate(
				{ _id: id },
				{ $set: { ...patch, updatedAt: new Date() } },
				{ returnDocument: 'after' }
			)
		);
	}

	async repairReservedSlug(id: string, slug: string): Promise<void> {
		await this.collection.updateOne(
			{ _id: id, slug: { $exists: false } },
			{ $set: { slug, updatedAt: new Date() } }
		);
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}
}
