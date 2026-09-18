import type { UserBucket, UserBucketStoreInstance } from '../types.js';
import type { FederationProvider } from '../../federation/types.js';
import { UniqueValueTaken } from '../conflicts.js';
import nanoid from '../../helpers/nanoid.js';

export class UserBucketStore implements UserBucketStoreInstance {
	private buckets = new Map<string, UserBucket>();

	/*
	 * The hostname uniqueness the two production backends get from a unique sparse index.
	 *
	 * The check and the write below are separated by no `await`, which on a single-threaded runtime is
	 * what makes this genuinely atomic rather than merely usually right. Written as a read-then-write
	 * with an await between them it would pass every test forever — the default run has no concurrency
	 * to lose the race to — and lose it in production, which is the divergence Principle III refuses to
	 * let pass silently.
	 */
	private hostHolder(host: string, exceptId?: string): UserBucket | undefined {
		for (const b of this.buckets.values()) {
			if (b.host === host && b._id !== exceptId) return b;
		}
		return undefined;
	}

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
		if (data.host !== undefined && this.hostHolder(data.host)) {
			throw new UniqueValueTaken('host', data.host);
		}

		const now = new Date();
		const bucket: UserBucket = {
			_id: data._id ?? nanoid(),
			name: data.name,
			slug: data.slug,
			...(data.host !== undefined ? { host: data.host } : {}),
			ownerGroupId: data.ownerGroupId,
			roles: data.roles ?? [],
			// A bucket accepts passwords unless someone says otherwise, and holds no providers until one is
			// configured. Defaulted here and on read, so a document written before these fields existed
			// behaves exactly as it did.
			passwordLogin: data.passwordLogin ?? true,
			federation: data.federation ?? [],
			registrationOpen: data.registrationOpen ?? true,
			emailVerificationRequired: data.emailVerificationRequired ?? false,
			verificationMethod: data.verificationMethod ?? 'link',
			// Off unless asked for: turning it on is a decision an operator makes, never one a
			// default makes for them.
			totpRequired: data.totpRequired ?? false,
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
		// Same reasoning in the other direction: undefined is falsy, and reading it as "not required"
		// is exactly right for a bucket written before the second factor existed.
		bucket.totpRequired ??= false;
		return bucket;
	}

	async find(id: string): Promise<UserBucket | null> {
		const bucket = this.buckets.get(id);
		return bucket ? this.withDefaults(bucket) : null;
	}

	async findBySlug(slug: string): Promise<UserBucket | null> {
		for (const b of this.buckets.values()) {
			if (b.slug === slug) return this.withDefaults(b);
		}
		return null;
	}

	/*
	 * Matched exactly, never normalised here. A store that folded case on read would answer a lookup the
	 * uniqueness check never saw, so two names that differ only in case could both be created and one of
	 * them would resolve to the other's bucket. Normalisation belongs at the edges — the router and the
	 * admin surface both go through lib/consts/request_host.ts — so that what is compared is what is
	 * stored.
	 */
	async findByHost(host: string): Promise<UserBucket | null> {
		for (const b of this.buckets.values()) {
			if (b.host === host) return this.withDefaults(b);
		}
		return null;
	}

	async setAddress(
		id: string,
		address: { slug?: string; host?: string }
	): Promise<UserBucket | null> {
		const b = this.buckets.get(id);
		if (!b) return null;
		if (address.host !== undefined && this.hostHolder(address.host, id)) {
			throw new UniqueValueTaken('host', address.host);
		}

		/* One form written, the other removed in the same step: a bucket holds one address, never both. */
		delete b.slug;
		delete b.host;
		Object.assign(b, address, { updatedAt: new Date() });
		return this.withDefaults(b);
	}

	async list(): Promise<UserBucket[]> {
		return [...this.buckets.values()].map((b) => this.withDefaults(b));
	}

	async listByGroup(groupId: string): Promise<UserBucket[]> {
		return [...this.buckets.values()]
			.filter((b) => b.ownerGroupId === groupId)
			.map((b) => this.withDefaults(b));
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
		const b = this.buckets.get(id);
		if (!b) return null;
		Object.assign(b, patch, { updatedAt: new Date() });
		return b;
	}

	async repairReservedSlug(id: string, slug: string): Promise<void> {
		const b = this.buckets.get(id);
		if (!b || b.slug) return;
		Object.assign(b, { slug, updatedAt: new Date() });
	}

	async destroy(id: string): Promise<void> {
		this.buckets.delete(id);
	}
}
