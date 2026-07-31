import crypto from 'crypto';
import { db } from './db.js';
import { userAreaFor } from '../../consts/storage_inventory.js';
import { type User, type UserStoreInstance } from '../types.js';

export class UserStore implements UserStoreInstance {
	name = 'redfox';

	constructor(name?: string) {
		if (name) {
			this.name = name;
		}
	}

	/* Composed through the inventory helper rather than concatenated here, so the `user_` prefix has
	 * one definition shared with whatever provisions these collections. */
	private get collectionName(): string {
		return userAreaFor(this.name);
	}

	async find(_id: string): Promise<User | null> {
		const result = await db
			.collection<User>(this.collectionName)
			.findOne({ _id });
		return result || null;
	}

	async findByEmail(email: string): Promise<User | null> {
		const result = await db
			.collection<User>(this.collectionName)
			.findOne({ email: email.toLowerCase() });
		return result || null;
	}

	async create(
		email: string,
		password: string,
		roles: string[] = [],
		verified = false
	): Promise<User> {
		const existingUser = await this.findByEmail(email);
		if (existingUser) {
			throw new Error('User with this email already exists');
		}
		const now = new Date();
		const user: User = {
			_id: crypto.randomUUID().replaceAll('-', ''),
			email: email.toLowerCase(),
			verified,
			password,
			active: true,
			roles,
			createdAt: now,
			updatedAt: now,
			lastLoginAt: null
		};
		await db.collection<User>(this.collectionName).insertOne(user);
		return user;
	}

	async list(): Promise<User[]> {
		return db.collection<User>(this.collectionName).find().toArray();
	}

	async update(
		_id: string,
		patch: Partial<Pick<User, 'roles' | 'active' | 'password' | 'verified'>>
	): Promise<User | null> {
		return db
			.collection<User>(this.collectionName)
			.findOneAndUpdate(
				{ _id },
				{ $set: { ...patch, updatedAt: new Date() } },
				{ returnDocument: 'after' }
			);
	}

	async destroy(_id: string): Promise<void> {
		await db.collection<User>(this.collectionName).deleteOne({ _id });
	}
}
