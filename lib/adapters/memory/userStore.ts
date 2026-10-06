import {
	clampPage,
	derivedKeysOf,
	FIELD_OF_KEY,
	matchesStored,
	storedFilterOf,
	storedPatchOf,
	uniqueValuesAfter
} from '../end_user_keys.js';
import {
	DuplicateEndUserError,
	MAX_END_USER_PAGE,
	type EndUserFilter,
	type EndUserPage,
	type EndUserPatch,
	type EndUserQueryResult,
	type User,
	type UserStoreInstance
} from '../types.js';

export class UserStore implements UserStoreInstance {
	private users = new Map<string, User>();
	name = 'redfox';

	constructor(name?: string) {
		if (name) {
			this.name = name;
		}
	}

	async find(_id: string): Promise<User | null> {
		return this.users.get(_id) || null;
	}

	// Test/dev seed: insert or overwrite a user with a caller-chosen id. Unlike
	// create(), it neither allocates an id nor enforces email uniqueness, so the
	// test harness can make the DB-backed findAccount resolve a session's
	// accountId. Not part of UserStoreInstance; only the in-memory store has it.
	seed(user: { _id: string } & Partial<Omit<User, '_id'>>): User {
		const now = new Date();
		const full: User = {
			_id: user._id,
			email: user.email ?? `${user._id}@example.com`,
			verified: user.verified ?? true,
			password: user.password ?? 'seeded',
			active: user.active ?? true,
			roles: user.roles ?? [],
			createdAt: user.createdAt ?? now,
			updatedAt: user.updatedAt ?? now,
			lastLoginAt: user.lastLoginAt ?? null,
			claims: user.claims,
			// Seeding a link is how a federation spec sets up "this account already signed in through that
			// provider once" without driving a whole round trip to establish it.
			federated: user.federated,
			// And seeding an enrolment is how a spec sets up "this account already holds an
			// authenticator" without driving the enrolment flow — which is what lets the operator-side
			// specs (clearing an enrolment) run without the interaction-side ones existing.
			totp: user.totp,
			userName: user.userName,
			externalId: user.externalId,
			provisionedBy: user.provisionedBy,
			profile: user.profile,
			lockedLocally: user.lockedLocally
		};
		Object.assign(full, derivedKeysOf(full));
		for (const [field, value] of Object.entries(full)) {
			if (value === undefined) Reflect.deleteProperty(full, field);
		}
		this.users.set(full._id, full);
		return full;
	}

	/*
	 * The unique indexes the other two stores declare, enforced by scan. Checked in the order a caller
	 * most wants to hear about: the email is the login.
	 */
	private duplicateOf(
		candidate: Pick<User, 'email' | 'userNameKey' | 'externalIdKey'>,
		excludeId?: string
	): DuplicateEndUserError | null {
		for (const field of ['email', 'userNameKey', 'externalIdKey'] as const) {
			const value = candidate[field];
			if (value === undefined) continue;
			for (const user of this.users.values()) {
				if (user._id !== excludeId && user[field] === value) {
					return new DuplicateEndUserError(FIELD_OF_KEY[field]);
				}
			}
		}
		return null;
	}

	async query(
		filter: EndUserFilter,
		page: EndUserPage
	): Promise<EndUserQueryResult> {
		const stored = storedFilterOf(filter);
		const { offset, limit } = clampPage(page, MAX_END_USER_PAGE);
		const matches = [...this.users.values()]
			.filter((user) => matchesStored(user, stored))
			.sort((a, b) => (a._id < b._id ? -1 : a._id > b._id ? 1 : 0));
		return {
			users: matches.slice(offset, offset + limit),
			totalResults: matches.length
		};
	}

	async findByEmail(email: string): Promise<User | null> {
		for (const user of this.users.values()) {
			if (user.email.toLowerCase() === email.toLowerCase()) {
				return user;
			}
		}
		return null;
	}

	/*
	 * The upstream-identity lookup. A scan here and a point read in MongoDB, which is what the per-bucket
	 * `{ 'federated.providerId': 1, 'federated.sub': 1 }` index exists for.
	 *
	 * Both values are compared exactly: `sub` is an opaque identifier chosen by the upstream provider, so
	 * case-folding or trimming it would merge two subjects the IdP considers distinct.
	 */
	async findByFederatedIdentity(
		providerId: string,
		sub: string
	): Promise<User | null> {
		for (const user of this.users.values()) {
			const linked = user.federated?.some(
				(link) => link.providerId === providerId && link.sub === sub
			);
			if (linked) {
				return user;
			}
		}
		return null;
	}

	async create(
		email: string,
		password: string,
		roles: string[] = [],
		verified = false,
		id?: string
	): Promise<User> {
		if (await this.findByEmail(email)) {
			throw new DuplicateEndUserError('email');
		}
		const now = new Date();
		const user: User = {
			// Caller-supplied when the account's audit entry has to name the id before the account
			// exists; generated here otherwise, as it always was.
			_id: id ?? crypto.randomUUID(),
			/*
			 * Normalised on write, matching the MongoDB store. The two disagreed until now — that one
			 * lower-cases here, this one kept whatever case it was given — and because `findByEmail`
			 * lower-cases both sides, sign-in behaved identically and the difference stayed invisible.
			 * It was not invisible to anything reading the *stored* value: the end-user delete route
			 * built its email-scoped cascade id from `user.email`, so under this adapter a mixed-case
			 * account's throttle and resend records were skipped, in silence, with the cascade
			 * reporting success. Constitution III.3 requires such a divergence to be converged or
			 * declared; this is the convergence.
			 */
			email: email.toLowerCase(),
			verified,
			password,
			active: true,
			roles,
			createdAt: now,
			updatedAt: now,
			lastLoginAt: null
		};
		this.users.set(user._id, user);
		return user;
	}

	async list(): Promise<User[]> {
		return [...this.users.values()];
	}

	async update(_id: string, patch: EndUserPatch): Promise<User | null> {
		const user = this.users.get(_id);
		if (!user) return null;
		const effective = await storedPatchOf(patch, async () => user);
		/* Refused before anything is written, as a unique index refuses the whole write. */
		const duplicate = this.duplicateOf(uniqueValuesAfter(user, effective), _id);
		if (duplicate) throw duplicate;

		Object.assign(user, effective, { updatedAt: new Date() });
		// Converged with the MongoDB store, which translates the same shape into `$unset`: a key present
		// with an undefined value means remove the field, not store an undefined one. Leaving the key
		// behind here would make the two adapters disagree about what a cleared enrolment looks like.
		for (const [field, value] of Object.entries(effective)) {
			if (value === undefined) {
				Reflect.deleteProperty(user, field);
			}
		}
		return user;
	}

	async destroy(_id: string): Promise<void> {
		this.users.delete(_id);
	}

	/*
	 * Not a no-op just because there is no collection to drop: this store is cached per bucket id
	 * (getUserStore), so a bucket re-created under a deleted bucket's id would inherit its users.
	 */
	async destroyArea(): Promise<void> {
		this.users.clear();
	}
}
