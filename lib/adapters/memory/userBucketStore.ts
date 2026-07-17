import type { UserBucket, UserBucketStoreInstance } from '../types.js';
import nanoid from '../../helpers/nanoid.js';

export class UserBucketStore implements UserBucketStoreInstance {
	private buckets = new Map<string, UserBucket>();

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
		this.buckets.set(bucket._id, bucket);
		return bucket;
	}

	async find(id: string): Promise<UserBucket | null> {
		return this.buckets.get(id) ?? null;
	}

	async list(): Promise<UserBucket[]> {
		return [...this.buckets.values()];
	}

	async listByManager(userId: string): Promise<UserBucket[]> {
		return [...this.buckets.values()].filter((b) =>
			b.managedBy.includes(userId)
		);
	}

	async update(
		id: string,
		patch: Partial<
			Pick<UserBucket, 'name' | 'managedBy' | 'roles' | 'authMethods'>
		>
	): Promise<UserBucket | null> {
		const b = this.buckets.get(id);
		if (!b) return null;
		Object.assign(b, patch, { updatedAt: new Date() });
		return b;
	}

	async destroy(id: string): Promise<void> {
		this.buckets.delete(id);
	}
}
