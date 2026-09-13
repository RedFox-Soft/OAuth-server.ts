/*
 * Reading a token response in these specs.
 *
 * The Eden client types a token response as a union of every shape the endpoint can return, and
 * narrowing it at each call site would need a discriminant the response does not carry. The
 * assertions are here, once, rather than scattered through four spec files — and each case still
 * asserts the value it reads, so a response that did not carry the field fails on the assertion
 * rather than on the cast.
 */
interface TokenResponse {
	data: unknown;
}

export function idTokenOf(res: TokenResponse): string {
	return (res.data as { id_token: string }).id_token;
}

export function refreshTokenOf(res: TokenResponse): string {
	return (res.data as { refresh_token: string }).refresh_token;
}
