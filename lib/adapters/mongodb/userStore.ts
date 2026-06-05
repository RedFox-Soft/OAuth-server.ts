import crypto from 'crypto';
import { db } from './db.js';
import { type User, type UserStoreInstance } from '../types.js';

export class UserStore implements UserStoreInstance {
	private prefix = 'user_';
	name = 'redfox';

	constructor(name?: string) {
		if (name) {
			this.name = name;
		}
	}

	async find(_id: string): Promise<User | null> {
		const result = await db
			.collection<User>(this.prefix + this.name)
			.findOne({ _id });
		return result || null;
	}

	async findByEmail(email: string): Promise<User | null> {
		const result = await db
			.collection<User>(this.prefix + this.name)
			.findOne({ email: email.toLowerCase() });
		return result || null;
	}

	async create(email: string, password: string): Promise<void> {
		const existingUser = await this.findByEmail(email);
		if (existingUser) {
			throw new Error('User with this email already exists');
		}

		await db.collection<User>(this.prefix + this.name).insertOne({
			_id: crypto.randomUUID().replaceAll('-', ''),
			email: email.toLowerCase(),
			verified: false,
			password,
			active: true,
			createdAt: new Date(),
			updatedAt: new Date(),
			lastLoginAt: null
		});
	}
}
