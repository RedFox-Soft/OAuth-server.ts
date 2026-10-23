/*
 * The identifiers of the assertion grants (specs/108), declared once. Import-free, because the client
 * validator reads them on every client resolution and the discovery document and the console read them too.
 */

/* RFC 8693 §2.1. */
export const TOKEN_EXCHANGE_GRANT =
	'urn:ietf:params:oauth:grant-type:token-exchange';
/* RFC 7523 §2.1, as updated by draft-ietf-oauth-rfc7523bis. */
export const JWT_BEARER_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-bearer';
/*
 * draft-parecki-oauth-jwt-dpop-grant-01 §3.1: the same grant for an assertion bound to a DPoP key. That
 * draft has expired, but ID-JAG -04 cites it normatively and uses it in its own DPoP example (§9.8.1.2.1),
 * so a client following the example sends it.
 */
export const JWT_DPOP_GRANT = 'urn:ietf:params:oauth:grant-type:jwt-dpop';

/* ID-JAG §7.2 and §8: the profile identifier in authorization server and client metadata. */
export const ID_JAG_PROFILE = 'urn:ietf:params:oauth:grant-profile:id-jag';
/* ID-JAG §4.3: the requested and issued token type. */
export const ID_JAG_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id-jag';
export { ID_JAG_JWT_TYPE } from './jwt_types.ts';

/* RFC 8693 §3: the subject token types the ID-JAG exchange accepts (ID-JAG §4.3). */
export const ID_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token';
export const REFRESH_TOKEN_TYPE =
	'urn:ietf:params:oauth:token-type:refresh_token';
