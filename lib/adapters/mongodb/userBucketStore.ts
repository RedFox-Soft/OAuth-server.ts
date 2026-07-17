import { db } from './db.js';
import type { UserBucket, UserBucketStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class UserBucketStore implements UserBucketStoreInstance {
	private collection = db.collection<UserBucket>('userBuckets');

	async create(data: {
		_id?: string;
		name: string;
		managedBy?: string[];
		roles?: string[];
		authMethods?: string[];
	}): Promise<UserBucket> {
		const now = new Date();
		const bucket: UserBucket = {
			_id: data._id ?? nanoid(),
			name: data.name,
			managedBy: data.managedBy ?? [],
			roles: data.roles ?? [],
			authMethods: data.authMethods ?? ['password'],
			createdAt: now,
			updatedAt: now
		};
		await this.collection.insertOne(bucket);
		return bucket;
	}

	async find(id: string): Promise<UserBucket | null> {
		return this.collection.findOne({ _id: id });
	}

	async list(): Promise<UserBucket[]> {
		return this.collection.find().toArray();
	}

	async listByManager(userId: string): Promise<UserBucket[]> {
		return this.collection.find({ managedBy: userId }).toArray();
	}

	async update(
		id: string,
		patch: Partial<
			Pick<UserBucket, 'name' | 'managedBy' | 'roles' | 'authMethods'>
		>
	): Promise<UserBucket | null> {
		return this.collection.findOneAndUpdate(
			{ _id: id },
			{ $set: { ...patch, updatedAt: new Date() } },
			{ returnDocument: 'after' }
		);
	}

	async destroy(id: string): Promise<void> {
		await this.collection.deleteOne({ _id: id });
	}
}
