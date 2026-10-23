/*
 * The explicit JWT types (the JOSE `typ` header) this server issues or consumes, declared once. One list, so a type
 * added later reaches both surfaces that refuse a token typed for another purpose — client authentication and the
 * assertion grants — and a token minted for one job can never be replayed as another (RFC 8725 §3.11).
 */

/* draft-ietf-oauth-rfc7523bis §4: the type a client authentication JWT SHOULD carry. */
export const CLIENT_AUTHENTICATION_JWT_TYPE = 'client-authentication+jwt';
/* ID-JAG §3.1: the explicit JWT type an ID-JAG MUST carry. */
export const ID_JAG_JWT_TYPE = 'oauth-id-jag+jwt';

export const RESERVED_JWT_TYPES: ReadonlySet<string> = new Set([
	CLIENT_AUTHENTICATION_JWT_TYPE,
	'dpop+jwt',
	'at+jwt',
	'logout+jwt',
	'secevent+jwt',
	'token-introspection+jwt',
	'global-token-revocation+jwt',
	ID_JAG_JWT_TYPE
]);
