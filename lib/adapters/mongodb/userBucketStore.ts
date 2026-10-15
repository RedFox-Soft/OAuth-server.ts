import { db } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import { STORE_AREAS } from '../../consts/storage_inventory.js';
import { provisionUserArea } from './provision.js';
import { documentOf } from '../documents.js';
import {
	UserBucket,
	type BucketAddressWrite,
	type BucketDeletion,
	type UserBucketStoreInstance
} from '../types.js';
import type { FederationProvider } from '../../federation/types.js';
import { UniqueValueTaken } from '../conflicts.js';
import nanoid from '../../helpers/nanoid.js';

/* The driver's duplicate-key code, classified here exactly as migrationLeaseStore classifies it. */
function isDuplicateKey(error: unknown): boolean {
	return (
		typeof error === 'object' &&
		error !== null &&
		'code' in error &&
		error.code === 11000
	);
}

// Buckets created before the verification settings existed have no stored values;
// project the safe defaults on read so callers always see the full shape. Defaulted before the
// check, which is what lets such a document pass it.
function bucketOf(bucket: Partial<UserBucket>): UserBucket {
	return documentOf(STORE_AREAS.userBuckets, UserBucket, {
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
	});
}

/*
 * Which unique name a duplicate-key error is about. Two unique indexes cover this area since specs/101 —
 * `host` and `slug` — and the driver reports the index's key pattern, so the refusal can name the field the
 * caller has to change rather than guessing from what the write happened to carry.
 */
function duplicatedField(error: unknown): 'slug' | 'host' | null {
	if (!isDuplicateKey(error)) return null;
	const pattern =
		typeof error === 'object' && error !== null && 'keyPattern' in error
			? error.keyPattern
			: undefined;
	if (typeof pattern === 'object' && pattern !== null && 'slug' in pattern) {
		return 'slug';
	}
	return 'host';
}

function withDefaults(bucket: Partial<UserBucket> | null): UserBucket | null {
	return bucket ? bucketOf(bucket) : null;
}

export class UserBucketStore implements UserBucketStoreInstance {
	private collection = db.collection<UserBucket>(STORE_AREAS.userBuckets);

	async create(data: {
		_id?: string;
		name: string;
		displayName?: string;
		slug?: string;
		host?: string;
		ownerGroupId: string;
		passwordLogin?: boolean;
		federation?: FederationProvider[];
		registrationOpen?: boolean;
		emailVerificationRequired?: boolean;
		verificationMethod?: UserBucket['verificationMethod'];
		totpRequired?: boolean;
		subdomain?: true;
	}): Promise<UserBucket> {
		const now = new Date();
		const bucket: UserBucket = {
			_id: data._id ?? nanoid(),
			name: data.name,
			...(data.displayName !== undefined
				? { displayName: data.displayName }
				: {}),
			slug: data.slug,
			/*
			 * Written only when present, never as an explicit undefined. A stored null would occupy the
			 * unique sparse index, so the second bucket created without a hostname would collide with the
			 * first — the failure the index is sparse to avoid.
			 */
			...(data.host !== undefined ? { host: data.host } : {}),
			...(data.subdomain ? { subdomain: true as const } : {}),
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
		try {
			await this.collection.insertOne(bucket, ABSENT_UNDEFINED);
		} catch (error) {
			const field = duplicatedField(error);
			if (field === 'slug' && data.slug !== undefined) {
				throw new UniqueValueTaken('slug', data.slug);
			}
			if (field === 'host' && data.host !== undefined) {
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
		address: BucketAddressWrite
	): Promise<UserBucket | null> {
		/* One form set, every other unset in the same update: a bucket holds one address. An absent
		 * hostname or slug must be *removed* rather than written null, or it would occupy its unique sparse
		 * index and collide with every other bucket that has none. Arrivals at the old address say nothing
		 * about the new one, so they go in the same update. */
		const unset: {
			host?: '';
			slug?: '';
			subdomain?: '';
			hostFirstSeenAt: '';
			hostLastSeenAt: '';
		} = {
			...(address.host === undefined ? { host: '' } : { slug: '' }),
			...(address.subdomain ? {} : { subdomain: '' }),
			hostFirstSeenAt: '',
			hostLastSeenAt: ''
		};
		try {
			return withDefaults(
				await this.collection.findOneAndUpdate(
					{ _id: id },
					{ $set: { ...address, updatedAt: new Date() }, $unset: unset },
					{ returnDocument: 'after' }
				)
			);
		} catch (error) {
			const field = duplicatedField(error);
			if (field === 'slug' && address.slug !== undefined) {
				throw new UniqueValueTaken('slug', address.slug);
			}
			if (field === 'host' && address.host !== undefined) {
				throw new UniqueValueTaken('host', address.host);
			}
			throw error;
		}
	}

	async list(): Promise<UserBucket[]> {
		return (await this.collection.find().toArray()).map(bucketOf);
	}

	async listByGroup(groupId: string): Promise<UserBucket[]> {
		return (
			await this.collection.find({ ownerGroupId: groupId }).toArray()
		).map(bucketOf);
	}

	async update(
		id: string,
		patch: Partial<
			Pick<
				UserBucket,
				| 'name'
				| 'displayName'
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
		/*
		 * A key present with an undefined value removes the field. `$set` cannot say that — the driver drops
		 * undefined values — so clearing a display name through it would leave the old name on every
		 * end-user page. The patch is split, as the user store's is.
		 */
		const set: Record<string, unknown> = { updatedAt: new Date() };
		const unset: Record<string, ''> = {};
		for (const [field, value] of Object.entries(
			patch as Record<string, unknown>
		)) {
			if (value === undefined) unset[field] = '';
			else set[field] = value;
		}
		return withDefaults(
			await this.collection.findOneAndUpdate(
				{ _id: id },
				// An empty $unset is rejected by MongoDB, so the operator only appears when it has work.
				Object.keys(unset).length
					? { $set: set, $unset: unset }
					: { $set: set },
				// A federation list carries providers whose optional secrets may be undefined.
				{ returnDocument: 'after', ...ABSENT_UNDEFINED }
			)
		);
	}

	async repairReservedSlug(id: string, slug: string): Promise<void> {
		await this.collection.updateOne(
			{ _id: id, slug: { $exists: false } },
			{ $set: { slug, updatedAt: new Date() } }
		);
	}

	/*
	 * Each transition's condition is in the filter of one `findOneAndUpdate`, so the datastore decides the
	 * race: of two callers, one matches and the other finds nothing.
	 */
	async scheduleDeletion(
		id: string,
		deletion: Omit<BucketDeletion, 'purge'>
	): Promise<UserBucket | null> {
		return withDefaults(
			await this.collection.findOneAndUpdate(
				{ _id: id, deletion: { $exists: false } },
				{ $set: { deletion, updatedAt: new Date() } },
				{ returnDocument: 'after', ...ABSENT_UNDEFINED }
			)
		);
	}

	async cancelDeletion(id: string, now: Date): Promise<UserBucket | null> {
		return withDefaults(
			await this.collection.findOneAndUpdate(
				{
					_id: id,
					deletion: { $exists: true },
					'deletion.purge.claimedUntil': { $not: { $gte: now } }
				},
				{ $unset: { deletion: '' }, $set: { updatedAt: new Date() } },
				{ returnDocument: 'after' }
			)
		);
	}

	async claimPurge(
		id: string,
		now: Date,
		until: Date,
		options: { due: boolean }
	): Promise<UserBucket | null> {
		return withDefaults(
			await this.collection.findOneAndUpdate(
				{
					_id: id,
					deletion: { $exists: true },
					'deletion.purge.claimedUntil': { $not: { $gte: now } },
					...(options.due ? { 'deletion.purgeAt': { $lte: now } } : {})
				},
				/* The dotted path keeps `recordedAt` beside it, so a retry never records twice. */
				{ $set: { 'deletion.purge.claimedUntil': until } },
				{ returnDocument: 'after' }
			)
		);
	}

	async markPurgeRecorded(id: string, at: Date): Promise<void> {
		await this.collection.updateOne(
			{ _id: id, 'deletion.purge': { $exists: true } },
			{ $set: { 'deletion.purge.recordedAt': at } }
		);
	}

	async releasePurge(id: string, until: Date): Promise<void> {
		/* Lapsed rather than removed, so `recordedAt` beside it survives and a retry never records twice. */
		await this.collection.updateOne(
			{ _id: id, 'deletion.purge.claimedUntil': until },
			{ $set: { 'deletion.purge.claimedUntil': new Date(0) } }
		);
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}
}
