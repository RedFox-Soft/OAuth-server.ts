import crypto from 'crypto';
import { entriesOf } from '../../helpers/_/object.js';
import { db } from './db.js';
import { ABSENT_UNDEFINED } from './write_options.js';
import { STORE_AREAS, userAreaFor } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import {
	clampPage,
	FIELD_OF_KEY,
	searchOf,
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
	type EndUserOrder,
	type EndUserPage,
	type EndUserPatch,
	type EndUserQueryResult,
	type EndUserTally,
	type EndUserTallyOptions,
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

/*
 * A text matched literally inside a regular expression. Every character the expression language gives a
 * meaning is preceded by a backslash, so a search for `a.b` cannot find `axb` and `.*` finds nothing it does
 * not spell. Built from a character list rather than a regex literal of escapes, which is the one place a
 * mistake here would be invisible.
 */
const BACKSLASH = String.fromCharCode(92);

function literalPattern(text: string): string {
	/* The escape character itself first, so the backslashes added below are not escaped again. */
	let escaped = text.split(BACKSLASH).join(BACKSLASH + BACKSLASH);
	for (const special of '.*+?^$()[]{}|') {
		escaped = escaped.split(special).join(BACKSLASH + special);
	}
	return escaped;
}

/*
 * The console's filters as MongoDB clauses, ANDed. The search is an anchored, case-sensitive prefix on the
 * stored lower-case keys, which is what lets the `email` and `userNameKey` indexes bound the scan; the state
 * tests are the tally's own (an enrolment or a lock is an object, anything else is none).
 */
function consoleClauses(filter: EndUserFilter): Record<string, unknown>[] {
	const clauses: Record<string, unknown>[] = [];
	const objectWhen = (wanted: boolean) =>
		wanted ? { $type: 'object' } : { $not: { $type: 'object' } };
	if (filter.search !== undefined) {
		const search = searchOf(filter.search);
		clauses.push({
			$or: [
				{ email: { $regex: `^${literalPattern(search.emailPrefix)}` } },
				{
					userNameKey: {
						$regex: `^${literalPattern(search.userNameKeyPrefix)}`
					}
				},
				{ _id: search.id }
			]
		});
	}
	if (filter.active !== undefined) clauses.push({ active: filter.active });
	if (filter.verified !== undefined)
		clauses.push({ verified: filter.verified });
	if (filter.locked !== undefined)
		clauses.push({ lockedLocally: objectWhen(filter.locked) });
	if (filter.totpEnrolled !== undefined)
		clauses.push({ totp: objectWhen(filter.totpEnrolled) });
	if (filter.local !== undefined)
		clauses.push({
			provisionedBy: filter.local
				? { $not: { $type: 'string' } }
				: { $type: 'string' }
		});
	return clauses;
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

	async findLinkedTo(providerId: string, limit?: number): Promise<User[]> {
		const cursor = db
			.collection<User>(this.collectionName)
			.find({ 'federated.providerId': providerId });
		const docs = await (
			limit === undefined ? cursor : cursor.limit(limit)
		).toArray();
		return docs
			.map((doc) => this.userOf(doc))
			.filter((u): u is User => u !== null);
	}

	/* A document matches once however many of its links name the provider, so this counts accounts, not links. */
	async countLinkedTo(providerId: string): Promise<number> {
		return db
			.collection<User>(this.collectionName)
			.countDocuments({ 'federated.providerId': providerId });
	}

	/*
	 * An enrolment is an object, so anything else — absent or null — is no authenticator; and `federated.0`
	 * not existing matches an absent, null or empty array alike. The PostgreSQL store counts the same states.
	 */
	async tally(options?: EndUserTallyOptions): Promise<EndUserTally> {
		const collection = db.collection<User>(this.collectionName);
		const unenrolled = { totp: { $not: { $type: 'object' as const } } };
		const [
			total,
			unverified,
			withoutAuthenticator,
			withoutLinkedIdentity,
			withoutEnabledLink,
			passwordWithoutAuthenticator
		] = await Promise.all([
			collection.countDocuments({}),
			collection.countDocuments({ verified: false }),
			collection.countDocuments(unenrolled),
			collection.countDocuments({ 'federated.0': { $exists: false } }),
			/*
			 * `$nin` matches a document whose `federated` holds no such provider — absent, null and an empty
			 * array included — and with no ids at all it matches every document, which is the reading wanted.
			 */
			collection.countDocuments({
				'federated.providerId': {
					$nin: [...(options?.enabledProviderIds ?? [])]
				}
			}),
			collection.countDocuments({ ...unenrolled, passwordSet: { $ne: false } })
		]);
		return {
			total,
			unverified,
			withoutAuthenticator,
			withoutLinkedIdentity,
			withoutEnabledLink,
			passwordWithoutAuthenticator
		};
	}

	async create(
		email: string,
		password: string,
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
		page: EndUserPage,
		order: EndUserOrder = 'id'
	): Promise<EndUserQueryResult> {
		/*
		 * Member names come from storedFilterOf and consoleClauses, never from the caller, so this object holds
		 * no operator a caller chose; a caller's text reaches it only as a value or as an escaped pattern.
		 */
		const clauses = consoleClauses(filter);
		/*
		 * A member of one bucket group (specs/089): the group's membership ids, then those users. One `$in`
		 * holds a group of tens of thousands, and the membership area's `groupId` index serves the read.
		 */
		if (filter.memberOf !== undefined) {
			const memberships = await db
				.collection<{ userId: string }>(STORE_AREAS.bucketGroupMembers)
				.find({ groupId: filter.memberOf }, { projection: { userId: 1 } })
				.toArray();
			clauses.push({ _id: { $in: memberships.map((m) => m.userId) } });
		}
		const stored =
			clauses.length === 0
				? storedFilterOf(filter)
				: { $and: [storedFilterOf(filter), ...clauses] };
		const { offset, limit } = clampPage(page, MAX_END_USER_PAGE);
		const collection = db.collection<User>(this.collectionName);
		const [found, totalResults] = await Promise.all([
			limit === 0
				? Promise.resolve([])
				: collection
						.find(stored)
						.sort(order === 'email' ? { email: 1 } : { _id: 1 })
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

	async findMany(ids: string[]): Promise<User[]> {
		if (ids.length === 0) return [];
		const found = await db
			.collection<User>(this.collectionName)
			.find({ _id: { $in: ids.slice(0, MAX_END_USER_PAGE) } })
			.toArray();
		return found.map((user) => documentOf(this.collectionName, User, user));
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
		for (const [field, value] of entriesOf(stored)) {
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
