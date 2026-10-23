import { decode as decodeJWT } from 'lib/helpers/jwt.ts';
import { idTokenOf } from '../acr/response.ts';

interface TokenResponse {
	data: unknown;
}

/* The two numbers every case here compares: when the ID token was issued, and when it says to come back. */
export function expiryOf(res: TokenResponse): {
	iat: number;
	sessionExpiry: unknown;
} {
	const { iat, session_expiry } = decodeJWT(idTokenOf(res)).payload;
	if (typeof iat !== 'number') throw new Error('expected an iat');
	return { iat, sessionExpiry: session_expiry };
}
