import type { UserBucket, UserBucketStoreInstance } from '../types.js';
import type { FederationProvider } from '../../federation/types.js';
import nanoid from '../../helpers/nanoid.js';

export class UserBucketStore implements UserBucketStoreInstance {
	private buckets = new Map<string, UserBucket>();

	async create(data: {
		_id?: string;
		name: string;
		managedBy?: string[];
		roles?: string[];
		passwordLogin?: boolean;
		federation?: FederationProvider[];
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
			// A bucket accepts passwords unless someone says otherwise, and holds no providers until one is
			// configured. Defaulted here and on read, so a document written before these fields existed
			// behaves exactly as it did.
			passwordLogin: data.passwordLogin ?? true,
			federation: data.federation ?? [],
			registrationOpen: data.registrationOpen ?? true,
			emailVerificationRequired: data.emailVerificationRequired ?? false,
			verificationMethod: data.verificationMethod ?? 'link',
			createdAt: now,
			updatedAt: now
		};
		this.buckets.set(bucket._id, bucket);
		return bucket;
	}

	/*
	 * Reads default the two federation fields, not just create(). A stored document predating them would
	 * otherwise read back with `passwordLogin: undefined`, which is falsy — silently closing the password
	 * door on every existing bucket.
	 */
	private withDefaults(bucket: UserBucket): UserBucket {
		bucket.passwordLogin ??= true;
		bucket.federation ??= [];
		return bucket;
	}

	async find(id: string): Promise<UserBucket | null> {
		const bucket = this.buckets.get(id);
		return bucket ? this.withDefaults(bucket) : null;
	}

	async list(): Promise<UserBucket[]> {
		return [...this.buckets.values()].map((b) => this.withDefaults(b));
	}

	async listByManager(userId: string): Promise<UserBucket[]> {
		return [...this.buckets.values()]
			.filter((b) => b.managedBy.includes(userId))
			.map((b) => this.withDefaults(b));
	}

	async update(
		id: string,
		patch: Partial<
			Pick<
				UserBucket,
				| 'name'
				| 'managedBy'
				| 'roles'
				| 'passwordLogin'
				| 'federation'
				| 'registrationOpen'
				| 'emailVerificationRequired'
				| 'verificationMethod'
			>
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
