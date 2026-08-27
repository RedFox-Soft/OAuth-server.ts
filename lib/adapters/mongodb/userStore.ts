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

	/*
	 * A point read on the per-bucket area's `{ 'federated.providerId': 1, 'federated.sub': 1 }` index.
	 * Both keys are inside one array element, so they must be matched with $elemMatch: two independent
	 * dotted conditions would also match an account holding provider A with one subject and provider B
	 * with another — which is a different account resolving as this identity.
	 */
	async findByFederatedIdentity(
		providerId: string,
		sub: string
	): Promise<User | null> {
		const result = await db
			.collection<User>(this.collectionName)
			.findOne({ federated: { $elemMatch: { providerId, sub } } });
		return result || null;
	}

	async create(
		email: string,
		password: string,
		roles: string[] = [],
		verified = false,
		id?: string
	): Promise<User> {
		const existingUser = await this.findByEmail(email);
		if (existingUser) {
			throw new Error('User with this email already exists');
		}
		const now = new Date();
		const user: User = {
			// Caller-supplied when the account's audit entry has to name the id before the account
			// exists; generated here otherwise, as it always was.
			_id: id ?? crypto.randomUUID().replaceAll('-', ''),
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
		patch: Partial<
			Pick<
				User,
				| 'roles'
				| 'active'
				| 'password'
				| 'verified'
				| 'claims'
				| 'federated'
				| 'totp'
			>
		>
	): Promise<User | null> {
		/*
		 * A key present with an undefined value means "remove this field", and `$set` cannot say that:
		 * the driver drops undefined values by default, so clearing an enrolment through `$set` would
		 * silently leave the secret in place — the account would still verify against an authenticator
		 * the operator believes they revoked, with nothing failing anywhere to reveal it. Splitting the
		 * patch is what makes `update(id, { totp: undefined })` mean what its one caller intends.
		 */
		const set: Record<string, unknown> = { updatedAt: new Date() };
		const unset: Record<string, ''> = {};
		for (const [field, value] of Object.entries(patch)) {
			if (value === undefined) {
				unset[field] = '';
			} else {
				set[field] = value;
			}
		}

		return db.collection<User>(this.collectionName).findOneAndUpdate(
			{ _id },
			// An empty $unset is rejected by MongoDB, so the operator only appears when it has work.
			Object.keys(unset).length ? { $set: set, $unset: unset } : { $set: set },
			{ returnDocument: 'after' }
		);
	}

	async destroy(_id: string): Promise<void> {
		await db.collection<User>(this.collectionName).deleteOne({ _id });
	}

	/*
	 * Dropping the collection is what closes the left-behind-collection hole: a deleted bucket used to
	 * leave `user_<bucket>` in the database for good, indexes and all.
	 */
	async destroyArea(): Promise<void> {
		await db.collection<User>(this.collectionName).drop();
	}
}
