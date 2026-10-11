import { entriesOf } from '../../helpers/_/object.js';
import crypto from 'crypto';

import { sql, type Sql } from './db.js';
import { docOf } from './json.js';
import { isUniqueViolation } from './sqlState.js';
import { userAreaFor } from '../../consts/storage_inventory.js';
import { documentOf } from '../documents.js';
import {
	clampPage,
	FIELD_OF_KEY,
	searchOf,
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
	type EndUserOrder,
	type EndUserPage,
	type EndUserPatch,
	type EndUserQueryResult,
	type EndUserTally,
	type EndUserTallyOptions,
	type UserStoreInstance
} from '../types.js';

/*
 * One equality per filter member, each written out with its own literal path. Spelled as a switch rather
 * than a map of path strings so that no path is ever spliced into SQL text: a field name in a query is
 * always one of these literals, and every value is a bound parameter.
 */
function equalityFor(
	handle: Sql,
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

function conditionsFor(handle: Sql, filter: StoredEndUserFilter) {
	let where = handle`TRUE`;
	for (const field of Object.keys(filter) as Array<keyof StoredEndUserFilter>) {
		const value = filter[field];
		if (value !== undefined) {
			where = handle`${where} AND ${equalityFor(handle, field, value)}`;
		}
	}
	return where;
}

/*
 * A text as a LIKE prefix that matches only itself: `%`, `_` and the escape character are each preceded by
 * a backslash, which is LIKE's escape character unless an ESCAPE clause names another — none here does, so
 * the pattern stays a plain parameter the planner can turn into an index range. Built from a character
 * rather than written as an escape sequence, so no layer of quoting can change what it says.
 */
const BACKSLASH = String.fromCharCode(92);

function likePrefix(text: string): string {
	/* The escape character itself first, so the backslashes added below are not escaped again. */
	let escaped = text.split(BACKSLASH).join(BACKSLASH + BACKSLASH);
	for (const wildcard of '%_') {
		escaped = escaped.split(wildcard).join(BACKSLASH + wildcard);
	}
	return `${escaped}%`;
}

/*
 * The console's filters, ANDed onto `where`. The search's two prefix arms are served by the per-bucket area's
 * `text_pattern_ops` indexes (`prefix: true` in lib/consts/storage_inventory.ts), which a default-collation
 * b-tree cannot do for LIKE. The state tests are the tally's own, so a filter and a count agree.
 */
function consoleConditionsFor(
	handle: Sql,
	where: ReturnType<typeof conditionsFor>,
	filter: EndUserFilter
) {
	let all = where;
	if (filter.search !== undefined) {
		const search = searchOf(filter.search);
		all = handle`${all} AND (
			doc->>'email' LIKE ${likePrefix(search.emailPrefix)}
			OR doc->>'userNameKey' LIKE ${likePrefix(search.userNameKeyPrefix)}
			OR id = ${search.id}
		)`;
	}
	if (filter.active !== undefined) {
		all = filter.active
			? handle`${all} AND doc->'active' = 'true'::jsonb`
			: handle`${all} AND doc->'active' = 'false'::jsonb`;
	}
	if (filter.verified !== undefined) {
		all = filter.verified
			? handle`${all} AND doc->'verified' = 'true'::jsonb`
			: handle`${all} AND doc->'verified' = 'false'::jsonb`;
	}
	if (filter.locked !== undefined) {
		all = filter.locked
			? handle`${all} AND jsonb_typeof(doc->'lockedLocally') = 'object'`
			: handle`${all} AND jsonb_typeof(doc->'lockedLocally') IS DISTINCT FROM 'object'`;
	}
	if (filter.totpEnrolled !== undefined) {
		all = filter.totpEnrolled
			? handle`${all} AND jsonb_typeof(doc->'totp') = 'object'`
			: handle`${all} AND jsonb_typeof(doc->'totp') IS DISTINCT FROM 'object'`;
	}
	if (filter.local !== undefined) {
		all = filter.local
			? handle`${all} AND jsonb_typeof(doc->'provisionedBy') IS DISTINCT FROM 'string'`
			: handle`${all} AND jsonb_typeof(doc->'provisionedBy') = 'string'`;
	}
	return all;
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

	async findLinkedTo(providerId: string, limit?: number): Promise<User[]> {
		const handle = sql();
		const match = [{ providerId }];
		const rows =
			limit === undefined
				? await handle`
					SELECT doc FROM ${handle(this.area)}
					WHERE doc->'federated' @> ${match}
				`
				: await handle`
					SELECT doc FROM ${handle(this.area)}
					WHERE doc->'federated' @> ${match}
					LIMIT ${limit}
				`;
		return rows
			.map((row) => this.userOf(row))
			.filter((u): u is User => u !== null);
	}

	/* The containment test `findLinkedTo` uses, so the two can never disagree about who is linked. */
	async countLinkedTo(providerId: string): Promise<number> {
		const handle = sql();
		const match = [{ providerId }];
		const rows = await handle<{ count: number }[]>`
			SELECT count(*)::int AS count FROM ${handle(this.area)}
			WHERE doc->'federated' @> ${match}
		`;
		return rows[0]?.count ?? 0;
	}

	/*
	 * One scan, one filter per state, matching the MongoDB store's tests: an enrolment is an object, so
	 * anything else — absent or a JSON null — is no authenticator; `federated` counts as unlinked unless it
	 * is a non-empty array — absent, null and empty alike.
	 */
	async tally(options?: EndUserTallyOptions): Promise<EndUserTally> {
		const handle = sql();
		/*
		 * `= ANY` over an empty array matches nothing, so with no enabled provider every account is without
		 * an enabled link — the reading wanted. A `federated` that is not an array holds no link at all.
		 */
		const enabled = handle.array(
			[...(options?.enabledProviderIds ?? [])],
			'text'
		);
		const rows = await handle<EndUserTally[]>`
			SELECT
				count(*)::int AS "total",
				count(*) FILTER (WHERE doc->'verified' = 'false'::jsonb)::int AS "unverified",
				count(*) FILTER (
					WHERE jsonb_typeof(doc->'totp') IS DISTINCT FROM 'object'
				)::int AS "withoutAuthenticator",
				count(*) FILTER (
					WHERE jsonb_typeof(doc->'federated') IS DISTINCT FROM 'array'
						OR doc->'federated' = '[]'::jsonb
				)::int AS "withoutLinkedIdentity",
				count(*) FILTER (
					WHERE NOT EXISTS (
						SELECT 1
						FROM jsonb_array_elements(
							CASE WHEN jsonb_typeof(doc->'federated') = 'array'
								THEN doc->'federated' ELSE '[]'::jsonb END
						) AS link
						WHERE link->>'providerId' = ANY(${enabled})
					)
				)::int AS "withoutEnabledLink",
				count(*) FILTER (
					WHERE jsonb_typeof(doc->'totp') IS DISTINCT FROM 'object'
						AND doc->'passwordSet' IS DISTINCT FROM 'false'::jsonb
				)::int AS "passwordWithoutAuthenticator"
			FROM ${handle(this.area)}
		`;
		const counted = rows.at(0);
		return {
			total: counted?.total ?? 0,
			unverified: counted?.unverified ?? 0,
			withoutAuthenticator: counted?.withoutAuthenticator ?? 0,
			withoutLinkedIdentity: counted?.withoutLinkedIdentity ?? 0,
			withoutEnabledLink: counted?.withoutEnabledLink ?? 0,
			passwordWithoutAuthenticator: counted?.passwordWithoutAuthenticator ?? 0
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
		page: EndUserPage,
		order: EndUserOrder = 'id'
	): Promise<EndUserQueryResult> {
		const stored = storedFilterOf(filter);
		const { offset, limit } = clampPage(page, MAX_END_USER_PAGE);
		const handle = sql();
		const where = consoleConditionsFor(
			handle,
			conditionsFor(handle, stored),
			filter
		);
		/* Byte order, as MongoDB's default comparison sorts, so a page is the same page on either backend. */
		const orderBy =
			order === 'email' ? handle`doc->>'email' COLLATE "C"` : handle`id`;
		const [rows, counted] = await Promise.all([
			limit === 0
				? Promise.resolve([])
				: handle`
					SELECT doc FROM ${handle(this.area)} WHERE ${where}
					ORDER BY ${orderBy} LIMIT ${limit} OFFSET ${offset}
				`,
			handle<
				{ total: number }[]
			>`SELECT count(*)::int AS total FROM ${handle(this.area)} WHERE ${where}`
		]);
		return {
			users: rows
				.map((row: unknown) => this.userOf(row))
				.filter((user: User | null): user is User => user !== null),
			totalResults: counted.at(0)?.total ?? 0
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
		for (const [field, value] of entriesOf(stored)) {
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
