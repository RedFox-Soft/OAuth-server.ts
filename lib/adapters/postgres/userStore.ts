import crypto from 'crypto';

import type { SQL } from 'bun';

import { sql } from './db.js';
import { docOf } from './json.js';
import { isUniqueViolation } from './sqlState.js';
import { userAreaFor } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import {
	clampPage,
	FIELD_OF_KEY,
	storedFilterOf,
	storedPatchOf,
	withCreateFields,
	type StoredEndUserFilter
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
 * One equality per filter member, each written out with its own literal path. Spelled as a switch rather
 * than a map of path strings so that no path is ever spliced into SQL text: a field name in a query is
 * always one of these literals, and every value is a bound parameter.
 */
function equalityFor(
	handle: SQL,
	field: keyof StoredEndUserFilter,
	value: string
) {
	switch (field) {
		case '_id':
			return handle`id = ${value}`;
		case 'userNameKey':
			return handle`doc->>'userNameKey' = ${value}`;
		case 'email':
			return handle`doc->>'email' = ${value}`;
		case 'provisionedBy':
			return handle`doc->>'provisionedBy' = ${value}`;
		case 'externalIdKey':
			return handle`doc->>'externalIdKey' = ${value}`;
	}
}

function conditionsFor(handle: SQL, filter: StoredEndUserFilter) {
	let where = handle`TRUE`;
	for (const field of Object.keys(filter) as Array<keyof StoredEndUserFilter>) {
		const value = filter[field];
		if (value !== undefined) {
			where = handle`${where} AND ${equalityFor(handle, field, value)}`;
		}
	}
	return where;
}

export class UserStore implements UserStoreInstance {
	name = 'redfox';

	constructor(name?: string) {
		if (name) {
			this.name = name;
		}
	}

	/* Composed through the inventory helper rather than concatenated here, so the `user_` prefix has
	 * one definition shared with whatever provisions these tables. */
	private get area(): string {
		return userAreaFor(this.name);
	}

	async find(_id: string): Promise<User | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)} WHERE id = ${_id}
		`;
		return this.userOf(rows[0]);
	}

	/*
	 * Lower-cased on read as well as on write. The declared unique index is on the stored value, so
	 * case-insensitivity comes from normalising at both ends rather than from `lower()` in the index —
	 * which keeps the normalisation in one place shared with MongoDB, instead of in two datastores'
	 * index definitions.
	 */
	async findByEmail(email: string): Promise<User | null> {
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->>'email' = ${email.toLowerCase()}
		`;
		return this.userOf(rows[0]);
	}

	/*
	 * Containment against one array element, which is what `$elemMatch` means on the other backend and
	 * why this cannot be two independent conditions. Matching `providerId` and `sub` separately would
	 * also match an account holding provider A with one subject and provider B with another — a
	 * different account resolving as this identity, which is an account takeover rather than a missed
	 * lookup.
	 *
	 * `@>` against an array of objects tests exactly this: some element contains both keys.
	 */
	async findByFederatedIdentity(
		providerId: string,
		sub: string
	): Promise<User | null> {
		const handle = sql();
		const match = [{ providerId, sub }];
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE doc->'federated' @> ${match}
			LIMIT 1
		`;
		return this.userOf(rows[0]);
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
				// exists; generated here otherwise.
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

		const handle = sql();
		try {
			await handle`
				INSERT INTO ${handle(this.area)} (id, doc, expires_at)
				VALUES (${user._id}, ${user}, NULL)
			`;
		} catch (error) {
			/*
			 * A unique index refused the insert — a concurrent registration of the same address the lookup
			 * above could not see, or a username or external identifier already held. Read back to name the
			 * field, so no driver text naming the value travels on into the error store.
			 */
			if (isUniqueViolation(error)) {
				throw (
					(await this.duplicateFor(user._id, user)) ??
					new DuplicateEndUserError('email')
				);
			}
			throw error;
		}

		return user;
	}

	async query(
		filter: EndUserFilter,
		page: EndUserPage
	): Promise<EndUserQueryResult> {
		const stored = storedFilterOf(filter);
		const { offset, limit } = clampPage(page, MAX_END_USER_PAGE);
		const handle = sql();
		const where = conditionsFor(handle, stored);
		const [rows, counted] = await Promise.all([
			limit === 0
				? Promise.resolve([])
				: handle`
					SELECT doc FROM ${handle(this.area)} WHERE ${where}
					ORDER BY id LIMIT ${limit} OFFSET ${offset}
				`,
			handle`SELECT count(*)::int AS total FROM ${handle(this.area)} WHERE ${where}`
		]);
		return {
			users: rows
				.map((row: unknown) => this.userOf(row))
				.filter((user: User | null): user is User => user !== null),
			totalResults: Number(counted[0]?.total ?? 0)
		};
	}

	async findMany(ids: string[]): Promise<User[]> {
		if (ids.length === 0) return [];
		const handle = sql();
		const rows = await handle`
			SELECT doc FROM ${handle(this.area)}
			WHERE id IN ${handle(ids.slice(0, MAX_END_USER_PAGE))}
		`;
		return rows
			.map((row: unknown) => this.userOf(row))
			.filter((user: User | null): user is User => user !== null);
	}

	/*
	 * Which unique key a refused write collided on. Read back rather than parsed from the driver's
	 * constraint name, because the index name is a provisioning detail that may be hashed when long
	 * (provision.ts `indexName`), while the values the write carried are in hand.
	 */
	private async duplicateFor(
		_id: string,
		stored: Partial<Pick<User, 'email' | 'userNameKey' | 'externalIdKey'>>
	): Promise<DuplicateEndUserError | null> {
		const handle = sql();
		for (const key of ['email', 'userNameKey', 'externalIdKey'] as const) {
			const value = stored[key];
			if (value === undefined) continue;
			const rows = await handle`
				SELECT 1 FROM ${handle(this.area)}
				WHERE ${equalityFor(handle, key, value)} AND id <> ${_id}
				LIMIT 1
			`;
			if (rows.length) return new DuplicateEndUserError(FIELD_OF_KEY[key]);
		}
		return null;
	}

	async list(): Promise<User[]> {
		const handle = sql();
		const rows = await handle`SELECT doc FROM ${handle(this.area)}`;
		return rows
			.map((row: unknown) => this.userOf(row))
			.filter((user: User | null): user is User => user !== null);
	}

	/*
	 * A key present with an undefined value means "remove this field", and a merge cannot say that:
	 * `doc || patch` would drop the key from the patch and leave the stored value untouched. Clearing a
	 * TOTP enrolment that way would silently leave the secret in place — the account would still verify
	 * against an authenticator the operator believes they revoked, with nothing failing anywhere to
	 * reveal it.
	 *
	 * So removals are subtracted before the merge. `doc - text[]` takes an empty array happily, which is
	 * why this needs no branch, unlike MongoDB's `$unset` that must be omitted when it has no work.
	 */
	async update(_id: string, patch: EndUserPatch): Promise<User | null> {
		const stored = await storedPatchOf(patch, () => this.find(_id));
		const set: Record<string, unknown> = { updatedAt: new Date() };
		const remove: string[] = [];
		for (const [field, value] of Object.entries(stored)) {
			if (value === undefined) remove.push(field);
			else set[field] = value;
		}

		const handle = sql();
		try {
			/*
			 * `handle.array`, not `${remove}::text[]`: Bun binds a bare JS array as text PostgreSQL cannot
			 * read as an array ("malformed array literal"), so every update threw — found by a round trip
			 * against a real server, which the in-memory suite cannot see.
			 */
			const rows = await handle`
				UPDATE ${handle(this.area)}
				SET doc = (doc - ${handle.array(remove, 'text')}) || ${set}
				WHERE id = ${_id}
				RETURNING doc
			`;
			return this.userOf(rows[0]);
		} catch (error) {
			if (!isUniqueViolation(error)) throw error;
			const duplicate = await this.duplicateFor(_id, stored);

			throw duplicate ?? error;
		}
	}

	async destroy(_id: string): Promise<void> {
		const handle = sql();
		await handle`DELETE FROM ${handle(this.area)} WHERE id = ${_id}`;
	}

	/*
	 * Dropping the table is what closes the left-behind-area hole: a deleted bucket used to leave
	 * `user_<bucket>` in the database for good, indexes and all.
	 */
	async destroyArea(): Promise<void> {
		const handle = sql();
		await handle.unsafe(`DROP TABLE IF EXISTS ${quoteArea(this.area)}`);
	}

	private userOf(row: unknown): User | null {
		const doc = docOf(row);
		return doc === undefined ? null : documentOf(this.area, User, doc);
	}
}

/*
 * DDL cannot take a bound parameter, so the one statement here that is not a query quotes its own
 * identifier. The area name is composed by `userAreaFor` from a bucket id the admin routes validate,
 * and doubling any embedded quote is what makes the composition safe rather than merely conventional.
 */
function quoteArea(name: string): string {
	return `"${name.replaceAll('"', '""')}"`;
}
