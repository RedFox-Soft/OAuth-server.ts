/*
 * Names an account's stored claims may not carry. `findAccount` spreads the stored claims last, so the
 * first three would stand in for the account's identity — `sub` also feeds the pairwise derivation —
 * and the rest for what the server itself asserts about a token or a sign-in.
 *
 * Import-free (lib/consts/ holds declarations) because two sides read it: the end-user service, which
 * refuses these names whatever surface a change arrives through, and the console, which refuses them on the
 * field before a request is sent. One list, so the console can never accept a name the server refuses.
 */
export const RESERVED_CLAIMS: readonly string[] = [
	'sub',
	'email',
	'email_verified',
	'iss',
	'aud',
	'exp',
	'iat',
	'nbf',
	'jti',
	'nonce',
	'azp',
	'acr',
	'amr',
	'auth_time',
	'sid',
	'at_hash',
	'c_hash',
	/* The server computes it at issuance (IPSIE SL1 §3.2.1); a stored value would tell an application a session lasts longer than it does. */
	'session_expiry',
	/* Always the user's actual bucket groups (lib/addon/account.ts); a stored value would forge authorization. */
	'groups'
];
