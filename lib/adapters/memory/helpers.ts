export function grantKeyFor(id: string) {
	return `grant:${id}`;
}

export function sessionUidKeyFor(id: string) {
	return `sessionUid:${id}`;
}

export function userCodeKeyFor(userCode: string) {
	return `userCode:${userCode}`;
}

export const grantable = new Set([
	'AccessToken',
	'AuthorizationCode',
	'RefreshToken',
	'DeviceCode',
	'BackchannelAuthenticationRequest'
]);
