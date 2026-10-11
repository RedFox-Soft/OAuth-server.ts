import { entriesOf } from '../helpers/_/object.js';
import type {
	BucketGroup,
	EndUserCreateFields,
	EndUserFilter,
	EndUserPatch,
	User
} from './types.js';

/*
 * The derived keys every user store maintains and every unique index on them holds. One definition for the
 * three adapters, because a key computed two ways is two indexes that disagree about what a duplicate is.
 *
 * Case-insensitive username uniqueness is a stored lowercase key rather than a collation, so MongoDB and
 * PostgreSQL agree by plain equality (specs/069 research R4). NFC first, so two spellings of the same
 * accented name are one name.
 */
export function userNameKeyOf(userName: string): string {
	return userName.normalize('NFC').toLowerCase();
}

/*
 * An external identifier means something only inside the connection that issued it (RFC 7643 §3.1), so its
 * key embeds the connection. Connection ids are nanoids, whose alphabet has no `:`, so the join is unambiguous.
 * A single scalar rather than a compound index: a sparse compound index would still index `(connection, null)`
 * and make two users of one connection without an identifier collide (research R5).
 */
export function externalIdKeyOf(
	provisionedBy: string,
	externalId: string
): string {
	return `${provisionedBy}:${externalId}`;
}

/*
 * A bucket group's name is unique within its bucket in any letter case (RFC 7643 declares Group `displayName`
 * `caseExact: false`; IPSIE §6.2.1 asks that names not repeat), so the key is the bucket and the username key
 * of the name — one rule for "the same name" across users and groups. Bucket ids are nanoids, with no `:`.
 */
export function displayNameKeyOf(
	bucketId: string,
	displayName: string
): string {
	return `${bucketId}:${userNameKeyOf(displayName)}`;
}

/* The membership record's id. Deterministic, so adding a member twice writes the same record once. */
export function membershipIdOf(groupId: string, userId: string): string {
	return `${groupId}:${userId}`;
}

/* The keys a group record should hold; `undefined` means the key must be absent. */
export function bucketGroupKeysOf(
	group: Pick<
		BucketGroup,
		'bucketId' | 'displayName' | 'externalId' | 'provisionedBy'
	>
): Pick<BucketGroup, 'displayNameKey' | 'externalIdKey'> {
	return {
		displayNameKey: displayNameKeyOf(group.bucketId, group.displayName),
		externalIdKey:
			group.externalId !== undefined && group.provisionedBy !== undefined
				? externalIdKeyOf(group.provisionedBy, group.externalId)
				: undefined
	};
}

type DerivedKeys = Pick<User, 'userNameKey' | 'externalIdKey'>;

/* The keys a record should hold given its identity fields; `undefined` means the key must be absent. */
export function derivedKeysOf(
	user: Pick<User, 'userName' | 'externalId' | 'provisionedBy'>
): DerivedKeys {
	return {
		userNameKey:
			user.userName === undefined ? undefined : userNameKeyOf(user.userName),
		externalIdKey:
			user.externalId !== undefined && user.provisionedBy !== undefined
				? externalIdKeyOf(user.provisionedBy, user.externalId)
				: undefined
	};
}

/*
 * A new account with its identity fields and their derived keys, ready for one insert. Undefined members are
 * left out rather than written, so no backend stores a key a unique index would then see as a value.
 */
export function withCreateFields(
	user: User,
	fields: EndUserCreateFields = {}
): User {
	const full: User = { ...user };
	for (const [field, value] of entriesOf(fields)) {
		if (value !== undefined) Object.assign(full, { [field]: value });
	}
	for (const [field, value] of entriesOf(derivedKeysOf(full))) {
		if (value !== undefined) Object.assign(full, { [field]: value });
	}
	return full;
}

/* Whether a patch touches a field the derived keys are computed from. */
export function touchesIdentity(patch: object): boolean {
	return ['userName', 'externalId', 'provisionedBy'].some((field) =>
		Object.prototype.hasOwnProperty.call(patch, field)
	);
}

export type StoredEndUserPatch = EndUserPatch & DerivedKeys;

type IdentityFields = Pick<User, 'userName' | 'externalId' | 'provisionedBy'>;

/*
 * The patch as it is written: email lowercased as on create, and the derived keys recomputed from the
 * record as it will be after the patch. `current` is read only when the patch touches an identity field,
 * which is why it is a thunk.
 */
export async function storedPatchOf(
	patch: EndUserPatch,
	current: () => Promise<IdentityFields | null>
): Promise<StoredEndUserPatch> {
	const stored: StoredEndUserPatch = { ...patch };
	if (typeof patch.email === 'string') {
		stored.email = patch.email.toLowerCase();
	}
	if (touchesIdentity(patch)) {
		const before = (await current()) ?? {};
		Object.assign(stored, derivedKeysOf({ ...before, ...patch }));
	}
	return stored;
}

/* The values a record's unique indexes will hold once `stored` is applied to `current`. */
export function uniqueValuesAfter(
	current: Pick<User, 'email' | 'userNameKey' | 'externalIdKey'>,
	stored: StoredEndUserPatch
): Pick<User, 'email' | 'userNameKey' | 'externalIdKey'> {
	const pick = <K extends 'userNameKey' | 'externalIdKey'>(key: K) =>
		Object.prototype.hasOwnProperty.call(stored, key)
			? stored[key]
			: current[key];
	return {
		email: stored.email ?? current.email,
		userNameKey: pick('userNameKey'),
		externalIdKey: pick('externalIdKey')
	};
}

/* Which identity field a stored unique key belongs to. */
export const FIELD_OF_KEY = {
	email: 'email',
	userNameKey: 'userName',
	externalIdKey: 'externalId'
} as const;

/*
 * A filter translated into the stored fields it compares, with values already normalised. The member names
 * on the left are the only field names any store puts in a query.
 */
export interface StoredEndUserFilter {
	_id?: string;
	userNameKey?: string;
	email?: string;
	provisionedBy?: string;
	externalIdKey?: string;
}

export function storedFilterOf(filter: EndUserFilter): StoredEndUserFilter {
	if (filter.externalId !== undefined && filter.provisionedBy === undefined) {
		throw new TypeError(
			'an external identifier is only meaningful with the connection that issued it'
		);
	}
	const stored: StoredEndUserFilter = {};
	if (filter.id !== undefined) stored._id = filter.id;
	if (filter.userName !== undefined)
		stored.userNameKey = userNameKeyOf(filter.userName);
	if (filter.email !== undefined) stored.email = filter.email.toLowerCase();
	if (filter.provisionedBy !== undefined)
		stored.provisionedBy = filter.provisionedBy;
	if (filter.externalId !== undefined && filter.provisionedBy !== undefined) {
		stored.externalIdKey = externalIdKeyOf(
			filter.provisionedBy,
			filter.externalId
		);
	}
	return stored;
}

/*
 * What one search text is compared with, per arm: the start of the stored email (lower-cased on write, so
 * lower-cased here), the start of the username key (derived by `userNameKeyOf`, so derived here the same
 * way), or the id exactly as typed — ids are case-sensitive, so lower-casing that arm would miss them.
 * One definition for the three stores, so "Ada" finds the same people on each.
 */
export interface EndUserSearch {
	emailPrefix: string;
	userNameKeyPrefix: string;
	id: string;
}

export function searchOf(search: string): EndUserSearch {
	return {
		emailPrefix: search.toLowerCase(),
		userNameKeyPrefix: userNameKeyOf(search),
		id: search
	};
}

/* Whether a record satisfies the console's filters — the in-memory store's reading of them. */
export function matchesConsoleFilter(
	user: User,
	filter: EndUserFilter
): boolean {
	if (filter.search !== undefined) {
		const search = searchOf(filter.search);
		const found =
			user.email.startsWith(search.emailPrefix) ||
			(user.userNameKey?.startsWith(search.userNameKeyPrefix) ?? false) ||
			user._id === search.id;
		if (!found) return false;
	}
	const isObject = (value: unknown) =>
		typeof value === 'object' && value !== null;
	if (filter.active !== undefined && user.active !== filter.active)
		return false;
	if (filter.verified !== undefined && user.verified !== filter.verified)
		return false;
	if (
		filter.locked !== undefined &&
		isObject(user.lockedLocally) !== filter.locked
	)
		return false;
	if (
		filter.totpEnrolled !== undefined &&
		isObject(user.totp) !== filter.totpEnrolled
	)
		return false;
	if (
		filter.local !== undefined &&
		(typeof user.provisionedBy !== 'string') !== filter.local
	)
		return false;
	return true;
}

/* Whether a record satisfies every member of a stored filter — the in-memory store's whole query engine. */
export function matchesStored(
	user: User,
	filter: StoredEndUserFilter
): boolean {
	return (Object.keys(filter) as Array<keyof StoredEndUserFilter>).every(
		(field) => user[field] === filter[field]
	);
}

/* `startIndex` below 1 reads from the start; `count` is held to [0, max]. */
export function clampPage(
	page: { startIndex: number; count: number },
	max: number
): { offset: number; limit: number } {
	const startIndex = Number.isFinite(page.startIndex)
		? Math.max(1, Math.floor(page.startIndex))
		: 1;
	const count = Number.isFinite(page.count)
		? Math.min(max, Math.max(0, Math.floor(page.count)))
		: 0;
	return { offset: startIndex - 1, limit: count };
}
