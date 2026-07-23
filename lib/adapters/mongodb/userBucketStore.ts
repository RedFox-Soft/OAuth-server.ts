import { db } from './db.js';
import type { UserBucket, UserBucketStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

// Buckets created before the verification settings existed have no stored values;
// project the safe defaults on read so callers always see the full shape.
function withDefaults(bucket: UserBucket | null): UserBucket | null {
	if (!bucket) return null;
	return {
		...bucket,
		registrationOpen: bucket.registrationOpen ?? true,
		emailVerificationRequired: bucket.emailVerificationRequired ?? false,
		verificationMethod: bucket.verificationMethod ?? 'link'
	};
}

export class UserBucketStore implements UserBucketStoreInstance {
	private collection = db.collection<UserBucket>('userBuckets');

	async create(data: {
		_id?: string;
		name: string;
		managedBy?: string[];
		roles?: string[];
		authMethods?: string[];
		registrationOpen?: boolean;
		emailVerificationRequired?: boolean;
		verificationMethod?: UserBucket['verificationMethod'];
	}): Promise<UserBucket> {
		const now = new Date();
		const bucket: UserBucket = {
			_id: data._id ?? nanoid(),
			name: data.name,
			managedBy: data.managedBy ?? [],
			roles: data.roles ?? [],
			authMethods: data.authMethods ?? ['password'],
			registrationOpen: data.registrationOpen ?? true,
			emailVerificationRequired: data.emailVerificationRequired ?? false,
			verificationMethod: data.verificationMethod ?? 'link',
			createdAt: now,
			updatedAt: now
		};
		await this.collection.insertOne(bucket);
		return bucket;
	}

	async find(id: string): Promise<UserBucket | null> {
		return withDefaults(await this.collection.findOne({ _id: id }));
	}

	async list(): Promise<UserBucket[]> {
		return (await this.collection.find().toArray()).map(
			(b) => withDefaults(b) as UserBucket
		);
	}

	async listByManager(userId: string): Promise<UserBucket[]> {
		return (await this.collection.find({ managedBy: userId }).toArray()).map(
			(b) => withDefaults(b) as UserBucket
		);
	}

	async update(
		id: string,
		patch: Partial<
			Pick<
				UserBucket,
				| 'name'
				| 'managedBy'
				| 'roles'
				| 'authMethods'
				| 'registrationOpen'
				| 'emailVerificationRequired'
				| 'verificationMethod'
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

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}
}
