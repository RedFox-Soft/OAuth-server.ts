import crypto from 'crypto';

import { sql } from './db.js';
import { docOf } from './json.js';
import { userAreaFor } from '../../consts/storage_inventory.js';
import { reviveDates } from './dates.js';
import { type User, type UserStoreInstance } from '../types.js';

const DATE_FIELDS = ['createdAt', 'updatedAt', 'lastLoginAt'] as const;

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
			// exists; generated here otherwise.
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

		const handle = sql();
		await handle`
			INSERT INTO ${handle(this.area)} (id, doc, expires_at)
			VALUES (${user._id}, ${user}, NULL)
		`;

		return user;
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
		const set: Record<string, unknown> = { updatedAt: new Date() };
		const remove: string[] = [];
		for (const [field, value] of Object.entries(patch)) {
			if (value === undefined) remove.push(field);
			else set[field] = value;
		}

		const handle = sql();
		const rows = await handle`
			UPDATE ${handle(this.area)}
			SET doc = (doc - ${remove}::text[]) || ${set}
			WHERE id = ${_id}
			RETURNING doc
		`;
		return this.userOf(rows[0]);
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
		const doc = docOf<User>(row);
		return doc === undefined ? null : reviveDates(doc, DATE_FIELDS);
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
