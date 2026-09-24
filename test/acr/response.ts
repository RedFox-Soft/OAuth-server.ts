import { isPlainObject } from 'lib/helpers/_/object.js';

/*
 * Reading a token response in these specs: the member a case needs, or a failed case when the
 * response did not carry it. `data` is `unknown` because the backchannel cases read a success and an
 * error body through the one field.
 */
interface TokenResponse {
	data: unknown;
}

function member(res: TokenResponse, name: string): string {
	const value = isPlainObject(res.data) ? res.data[name] : undefined;
	if (typeof value !== 'string') {
		throw new Error(`expected ${name} in the token response`);
	}
	return value;
}

export function idTokenOf(res: TokenResponse): string {
	return member(res, 'id_token');
}

export function refreshTokenOf(res: TokenResponse): string {
	return member(res, 'refresh_token');
}
