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
		roles: string[] = []
	): Promise<User> {
		if (await this.findByEmail(email)) {
			throw new Error('User with this email already exists');
		}
		const now = new Date();
		const user: User = {
			_id: crypto.randomUUID(),
			email,
			verified: false,
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
		patch: Partial<Pick<User, 'roles' | 'active' | 'password'>>
	): Promise<User | null> {
		const user = this.users.get(_id);
		if (!user) return null;
		Object.assign(user, patch, { updatedAt: new Date() });
		return user;
	}
}
