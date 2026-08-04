import { type User, type UserStoreInstance } from '../types.js';

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
			claims: user.claims
		};
		this.users.set(full._id, full);
		return full;
	}

	async findByEmail(email: string): Promise<User | null> {
		for (const user of this.users.values()) {
			if (user.email.toLowerCase() === email.toLowerCase()) {
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
			throw new Error('User with this email already exists');
		}
		const now = new Date();
		const user: User = {
			// Caller-supplied when the account's audit entry has to name the id before the account
			// exists; generated here otherwise, as it always was.
			_id: id ?? crypto.randomUUID(),
			email,
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

	async update(
		_id: string,
		patch: Partial<Pick<User, 'roles' | 'active' | 'password' | 'verified'>>
	): Promise<User | null> {
		const user = this.users.get(_id);
		if (!user) return null;
		Object.assign(user, patch, { updatedAt: new Date() });
		return user;
	}

	async destroy(_id: string): Promise<void> {
		this.users.delete(_id);
	}
}
