import { type User } from '../types.js';

export class UserStore {
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

	async create(email: string, password: string): Promise<void> {
		if (this.users.has(email.toLowerCase())) {
			throw new Error('User with this email already exists');
		}
		const _id = crypto.randomUUID();

		this.users.set(_id, {
			_id,
			email,
			verified: false,
			password,
			active: true,
			createdAt: new Date(),
			updatedAt: new Date(),
			lastLoginAt: null
		});
	}
}
