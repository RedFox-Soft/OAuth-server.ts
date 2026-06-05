export type GrantKey = `grant:${string}`;
export type SessionUidKey = `sessionUid:${string}`;
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

export function sessionUidKeyFor(id: string): SessionUidKey {
	return `sessionUid:${id}`;
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
