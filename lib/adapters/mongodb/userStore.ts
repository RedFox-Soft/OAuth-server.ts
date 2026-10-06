import crypto from 'crypto';
import { db } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import { userAreaFor } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import {
	clampPage,
	FIELD_OF_KEY,
	storedFilterOf,
	storedPatchOf,
	withCreateFields
} from '../end_user_keys.js';
import {
	DuplicateEndUserError,
	MAX_END_USER_PAGE,
	User,
	type EndUserCreateFields,
	type EndUserFilter,
	type EndUserPage,
	type EndUserPatch,
	type EndUserQueryResult,
	type UserStoreInstance
} from '../types.js';

/*
 * The field a refused write collided on, from the index MongoDB names in the error. An E11000 on an index
 * this store does not know is a defect, not a duplicate, and is rethrown by the caller.
 */
function duplicateFrom(error: unknown): DuplicateEndUserError | null {
	if (
		typeof error !== 'object' ||
		error === null ||
		!('code' in error) ||
		error.code !== 11000
	) {
		return null;
	}
	const pattern =
		'keyPattern' in error && typeof error.keyPattern === 'object'
			? Object.keys(error.keyPattern ?? {})
			: [];
	for (const key of ['email', 'userNameKey', 'externalIdKey'] as const) {
		if (pattern.includes(key))
			return new DuplicateEndUserError(FIELD_OF_KEY[key]);
	}
	return null;
}

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

	private userOf(found: unknown): User | null {
		return found ? documentOf(this.collectionName, User, found) : null;
	}

	async find(_id: string): Promise<User | null> {
		const result = await db
			.collection<User>(this.collectionName)
			.findOne({ _id });
		return this.userOf(result);
	}

	async findByEmail(email: string): Promise<User | null> {
		const result = await db
			.collection<User>(this.collectionName)
			.findOne({ email: email.toLowerCase() });
		return this.userOf(result);
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
		return this.userOf(result);
	}

	async create(
		email: string,
		password: string,
		roles: string[] = [],
		verified = false,
		id?: string,
		fields?: EndUserCreateFields
	): Promise<User> {
		const existingUser = await this.findByEmail(email);
		if (existingUser) {
			throw new DuplicateEndUserError('email');
		}
		const now = new Date();
		const user: User = withCreateFields(
			{
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
			},
			fields
		);
		try {
			await db
				.collection<User>(this.collectionName)
				.insertOne(user, ABSENT_UNDEFINED);
		} catch (error) {
			/*
			 * A unique index refused the insert — a concurrent registration of the same address the lookup
			 * above could not see, or a username or external identifier already held. Named by the index
			 * that refused it, so the driver's E11000 text, which quotes the value, never reaches the error
			 * store.
			 */
			const duplicate = duplicateFrom(error);
			if (duplicate) throw duplicate;
			throw error;
		}
		return user;
	}

	async query(
		filter: EndUserFilter,
		page: EndUserPage
	): Promise<EndUserQueryResult> {
		/* Member names come from storedFilterOf, never from the caller, so this object holds no operator. */
		const stored = storedFilterOf(filter);
		const { offset, limit } = clampPage(page, MAX_END_USER_PAGE);
		const collection = db.collection<User>(this.collectionName);
		const [found, totalResults] = await Promise.all([
			limit === 0
				? Promise.resolve([])
				: collection
						.find(stored)
						.sort({ _id: 1 })
						.skip(offset)
						.limit(limit)
						.toArray(),
			collection.countDocuments(stored)
		]);
		return {
			users: found.map((user) => documentOf(this.collectionName, User, user)),
			totalResults
		};
	}

	async list(): Promise<User[]> {
		const found = await db
			.collection<User>(this.collectionName)
			.find()
			.toArray();
		return found.map((user) => documentOf(this.collectionName, User, user));
	}

	async update(_id: string, patch: EndUserPatch): Promise<User | null> {
		/*
		 * A key present with an undefined value means "remove this field", and `$set` cannot say that:
		 * the driver drops undefined values by default, so clearing an enrolment through `$set` would
		 * silently leave the secret in place — the account would still verify against an authenticator
		 * the operator believes they revoked, with nothing failing anywhere to reveal it. Splitting the
		 * patch is what makes `update(id, { totp: undefined })` mean what its one caller intends.
		 */
		const stored = await storedPatchOf(patch, () => this.find(_id));
		const set: Record<string, unknown> = { updatedAt: new Date() };
		const unset: Record<string, ''> = {};
		for (const [field, value] of Object.entries(stored)) {
			if (value === undefined) {
				unset[field] = '';
			} else {
				set[field] = value;
			}
		}

		try {
			const updated = await db
				.collection<User>(this.collectionName)
				.findOneAndUpdate(
					{ _id },
					// An empty $unset is rejected by MongoDB, so the operator only appears when it has work.
					Object.keys(unset).length
						? { $set: set, $unset: unset }
						: { $set: set },
					{ returnDocument: 'after' }
				);
			return this.userOf(updated);
		} catch (error) {
			const duplicate = duplicateFrom(error);

			if (duplicate) throw duplicate;
			throw error;
		}
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
