import type {
	BucketAddressWrite,
	BucketDeletion,
	UserBucket,
	UserBucketStoreInstance
} from '../types.js';
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

	/* The same, for the unique sparse index on `slug` (specs/101): a subdomain made the slug an origin. */
	private slugHolder(slug: string, exceptId?: string): UserBucket | undefined {
		for (const b of this.buckets.values()) {
			if (b.slug === slug && b._id !== exceptId) return b;
		}
		return undefined;
	}

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
		planId?: string;
	}): Promise<UserBucket> {
		if (data.host !== undefined && this.hostHolder(data.host)) {
			throw new UniqueValueTaken('host', data.host);
		}
		if (data.slug !== undefined && this.slugHolder(data.slug)) {
			throw new UniqueValueTaken('slug', data.slug);
		}

		const now = new Date();
		const bucket: UserBucket = {
			_id: data._id ?? nanoid(),
			name: data.name,
			...(data.displayName !== undefined
				? { displayName: data.displayName }
				: {}),
			slug: data.slug,
			...(data.host !== undefined ? { host: data.host } : {}),
			...(data.subdomain ? { subdomain: true as const } : {}),
			...(data.planId !== undefined ? { planId: data.planId } : {}),
			ownerGroupId: data.ownerGroupId,
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
		// As held, not as typed: a document stored before these fields existed has none of them.
		const held: Partial<
			Pick<UserBucket, 'passwordLogin' | 'federation' | 'totpRequired'>
		> = bucket;
		held.passwordLogin ??= true;
		held.federation ??= [];
		// Same reasoning in the other direction: undefined is falsy, and reading it as "not required"
		// is exactly right for a bucket written before the second factor existed.
		held.totpRequired ??= false;
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
		address: BucketAddressWrite
	): Promise<UserBucket | null> {
		const b = this.buckets.get(id);
		if (!b) return null;
		if (address.host !== undefined && this.hostHolder(address.host, id)) {
			throw new UniqueValueTaken('host', address.host);
		}
		if (address.slug !== undefined && this.slugHolder(address.slug, id)) {
			throw new UniqueValueTaken('slug', address.slug);
		}

		/* One form written, every other removed in the same step: a bucket holds one address. */
		delete b.slug;
		delete b.host;
		delete b.subdomain;
		/* Arrivals at the old address say nothing about the new one. */
		delete b.hostFirstSeenAt;
		delete b.hostLastSeenAt;
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
		const b = this.buckets.get(id);
		if (!b) return null;
		/*
		 * A key present with an undefined value removes the field, as the other two backends do — leaving
		 * it as an own property holding undefined would read back differently from them.
		 */
		for (const [field, value] of Object.entries(
			patch as Record<string, unknown>
		)) {
			if (value === undefined) Reflect.deleteProperty(b, field);
			else Reflect.set(b, field, value);
		}
		b.updatedAt = new Date();
		return b;
	}

	async setPlan(id: string, planId: string): Promise<UserBucket | null> {
		const b = this.buckets.get(id);
		if (!b) return null;
		Object.assign(b, { planId, updatedAt: new Date() });
		return b;
	}

	async repairReservedSlug(id: string, slug: string): Promise<void> {
		const b = this.buckets.get(id);
		if (!b || b.slug) return;
		Object.assign(b, { slug, updatedAt: new Date() });
	}

	/*
	 * Each transition below checks and writes with no `await` between, which is what makes it the
	 * compare-and-set the two production backends get from one conditional statement — the reasoning
	 * `hostHolder` gives above.
	 */
	async scheduleDeletion(
		id: string,
		deletion: Omit<BucketDeletion, 'purge'>
	): Promise<UserBucket | null> {
		const b = this.buckets.get(id);
		if (!b || b.deletion) return null;
		Object.assign(b, { deletion: { ...deletion }, updatedAt: new Date() });
		return this.withDefaults(b);
	}

	async cancelDeletion(id: string, now: Date): Promise<UserBucket | null> {
		const b = this.buckets.get(id);
		if (!b?.deletion || claimLive(b.deletion, now)) return null;
		delete b.deletion;
		b.updatedAt = new Date();
		return this.withDefaults(b);
	}

	async claimPurge(
		id: string,
		now: Date,
		until: Date,
		options: { due: boolean }
	): Promise<UserBucket | null> {
		const b = this.buckets.get(id);
		const deletion = b?.deletion;
		if (!b || !deletion || claimLive(deletion, now)) return null;
		if (options.due && deletion.purgeAt.getTime() > now.getTime()) return null;
		b.deletion = {
			...deletion,
			purge: { ...deletion.purge, claimedUntil: until }
		};
		return this.withDefaults(b);
	}

	async markPurgeRecorded(id: string, at: Date): Promise<void> {
		const deletion = this.buckets.get(id)?.deletion;
		if (!deletion?.purge) return;
		deletion.purge = { ...deletion.purge, recordedAt: at };
	}

	async releasePurge(id: string, until: Date): Promise<void> {
		const deletion = this.buckets.get(id)?.deletion;
		if (deletion?.purge?.claimedUntil.getTime() !== until.getTime()) return;
		deletion.purge = { ...deletion.purge, claimedUntil: LAPSED };
	}

	async destroy(id: string): Promise<void> {
		this.buckets.delete(id);
	}
}

/* A released claim: in the past, so the next claim is taken at once; `recordedAt` beside it is kept. */
const LAPSED = new Date(0);

function claimLive(deletion: BucketDeletion, now: Date): boolean {
	const until = deletion.purge?.claimedUntil;
	return until !== undefined && until.getTime() >= now.getTime();
}
