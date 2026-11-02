export type GrantKey = `grant:${string}`;
export type UidKey = `uid:${string}:${string}`;
export type UserCodeKey = `userCode:${string}`;
export type ModelStorageKey<TModelName extends string> =
	`${TModelName}:${string}`;

export function modelKeyFor<TModelName extends string>(
	model: TModelName,
	id: string
): ModelStorageKey<TModelName> {
	return `${model}:${id}`;
}

export function grantKeyFor(id: string): GrantKey {
	return `grant:${id}`;
}

/*
 * Per model, as MongoDB's and PostgreSQL's `findByUid` read one collection: a session and a connect link
 * (specs/119) are both found by their uid, and one must never answer for the other.
 */
export function uidKeyFor(model: string, uid: string): UidKey {
	return `uid:${model}:${uid}`;
}

export function userCodeKeyFor(userCode: string): UserCodeKey {
	return `userCode:${userCode}`;
}

export const grantable = new Set([
	'AccessToken',
	'AuthorizationCode',
	'RefreshToken',
	'DeviceCode',
	'BackchannelAuthenticationRequest'
]);
