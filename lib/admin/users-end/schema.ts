import { t } from 'elysia';

/*
 * The claims an account releases beyond the ones the server derives. Replaced whole by an edit, never
 * merged, so what an operator sends is exactly what the account then holds. Which of them a client
 * actually receives is the `claims` setting's decision, not this record's.
 */
const EndUserClaims = t.Record(t.String(), t.Unknown());

/*
 * Names an account's stored claims may not carry. `findAccount` spreads the stored claims last, so the
 * first three would stand in for the account's identity — `sub` also feeds the pairwise derivation —
 * and the rest for what the server itself asserts about a token or a sign-in.
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
	'c_hash'
];

export const CreateEndUserBody = t.Object({
	email: t.String({ minLength: 3 }),
	password: t.String({ minLength: 8 }),
	roles: t.Optional(t.Array(t.String())),
	claims: t.Optional(EndUserClaims)
});

export const UpdateEndUserBody = t.Object({
	roles: t.Optional(t.Array(t.String())),
	active: t.Optional(t.Boolean()),
	claims: t.Optional(EndUserClaims)
});

export const ResetPasswordBody = t.Object({
	password: t.String({ minLength: 8 })
});
