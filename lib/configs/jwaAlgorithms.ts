import { getAlgorithm } from 'lib/configs/verifyJWKs.js';
import { publicJWKS } from './keystore.js';
import {
	type asymmetricSigningAlgType,
	type encryptionEncValues,
	type encryptionAlgValues,
	type signingAlgValues
} from './jwaConsts.js';

/*
 * clientAuthSigningAlgValues
 *
 * description: JWS "alg" Algorithm values the authorization server supports for signed JWT Client Authentication
 */
export const clientAuthSigningAlgValues: signingAlgValues[] = [
	'HS256',
	'RS256',
	'PS256',
	'ES256',
	'Ed25519',
	'EdDSA'
];

/*
 * What the instance's own keys sign and decrypt with, read from the live key set on every call rather
 * than from the one the server booted with. A key generated from the console signs at once; before
 * 2026-09-30 these lists were computed when this module loaded, so discovery never advertised the new
 * algorithm and a client could not register for it until a restart. Symmetric algorithms use the
 * client's own secret and are added by hand.
 */
function live() {
	return getAlgorithm(publicJWKS.keys);
}

// JWS algorithms the server signs ID Tokens with.
export const idTokenSigningAlgValues = (): signingAlgValues[] => [
	'HS256',
	...live().sign
];
// JWS algorithms the server signs UserInfo responses with.
export const userinfoSigningAlgValues = (): signingAlgValues[] => [
	'HS256',
	...live().sign
];
// JWS algorithms the server signs JWT introspection responses with.
export const introspectionSigningAlgValues = (): signingAlgValues[] => [
	'HS256',
	...live().sign
];
// JWS algorithms the server signs JWT authorization responses (JARM) with.
export const authorizationSigningAlgValues = (): signingAlgValues[] => [
	'HS256',
	...live().sign
];
// JWE algorithms the server accepts encrypted Request Objects (JAR) under.
export const requestObjectEncryptionAlgValues = (): encryptionAlgValues[] => [
	...live().enc,
	'A128KW',
	'A256KW',
	'dir'
];

/*
 * requestObjectSigningAlgValues
 *
 * description: JWS "alg" Algorithm values the authorization server supports to receive signed Request Objects (`JAR`) with
 */
export const requestObjectSigningAlgValues: signingAlgValues[] = [
	'HS256',
	'HS384',
	'RS256',
	'PS256',
	'ES256',
	'Ed25519',
	'EdDSA'
];

/*
 * backchannelAuthenticationRequestSigningAlgValues
 *
 * description: JWS "alg" Algorithm values the authorization server supports to receive signed Backchannel Authentication Request Objects (`JAR`) with
 */
export const backchannelAuthenticationRequestSigningAlgValues: asymmetricSigningAlgType[] =
	['RS256', 'PS256', 'ES256', 'Ed25519', 'EdDSA'];

/*
 * idTokenEncryptionAlgValues
 *
 * description: JWE "alg" Algorithm values the authorization server supports for ID Token encryption
 */
export const idTokenEncryptionAlgValues: encryptionAlgValues[] = [
	'A128KW',
	'A256KW',
	'ECDH-ES',
	'RSA-OAEP',
	'RSA-OAEP-256',
	'dir'
];
/*
 * userinfoEncryptionAlgValues
 *
 * description: JWE "alg" Algorithm values the authorization server supports for UserInfo Response encryption
 */
export const userinfoEncryptionAlgValues: encryptionAlgValues[] = [
	'A128KW',
	'A256KW',
	'ECDH-ES',
	'RSA-OAEP',
	'RSA-OAEP-256',
	'dir'
];
/*
 * introspectionEncryptionAlgValues
 *
 * description: JWE "alg" Algorithm values the authorization server supports for JWT Introspection response
 * encryption
 */
export const introspectionEncryptionAlgValues: encryptionAlgValues[] = [
	'A128KW',
	'A256KW',
	'ECDH-ES',
	'RSA-OAEP',
	'RSA-OAEP-256',
	'dir'
];
/*
 * authorizationEncryptionAlgValues
 *
 * description: JWE "alg" Algorithm values the authorization server supports for JWT Authorization response (`JARM`)
 * encryption
 */
export const authorizationEncryptionAlgValues: encryptionAlgValues[] = [
	'A128KW',
	'A256KW',
	'ECDH-ES',
	'RSA-OAEP',
	'RSA-OAEP-256',
	'dir'
];
/*
 * idTokenEncryptionEncValues
 *
 * description: JWE "enc" Content Encryption Algorithm values the authorization server supports to encrypt ID Tokens with
 */
export const idTokenEncryptionEncValues: encryptionEncValues[] = [
	'A128CBC-HS256',
	'A128GCM',
	'A256CBC-HS512',
	'A256GCM'
];
/*
 * requestObjectEncryptionEncValues
 *
 * description: JWE "enc" Content Encryption Algorithm values the authorization server supports to decrypt Request Objects (`JAR`) with
 */
export const requestObjectEncryptionEncValues: encryptionEncValues[] = [
	'A128CBC-HS256',
	'A192CBC-HS384',
	'A128GCM',
	'A256CBC-HS512',
	'A256GCM'
];
/*
 * userinfoEncryptionEncValues
 *
 * description: JWE "enc" Content Encryption Algorithm values the authorization server supports to encrypt UserInfo responses with
 */
export const userinfoEncryptionEncValues: encryptionEncValues[] = [
	'A128CBC-HS256',
	'A128GCM',
	'A256CBC-HS512',
	'A256GCM'
];
/*
 * introspectionEncryptionEncValues
 *
 * description: JWE "enc" Content Encryption Algorithm values the authorization server supports to encrypt JWT Introspection responses with
 */
export const introspectionEncryptionEncValues: encryptionEncValues[] = [
	'A128CBC-HS256',
	'A128GCM',
	'A256CBC-HS512',
	'A256GCM'
];
/*
 * authorizationEncryptionEncValues
 *
 * description: JWE "enc" Content Encryption Algorithm values the authorization server supports to encrypt JWT Authorization Responses (`JARM`) with
 */
export const authorizationEncryptionEncValues: encryptionEncValues[] = [
	'A128CBC-HS256',
	'A128GCM',
	'A256CBC-HS512',
	'A256GCM'
];
/*
 * dPoPSigningAlgValues
 *
 * description: JWS "alg" Algorithm values the authorization server supports to verify signed DPoP proof JWTs with
 */
export const dPoPSigningAlgValues: asymmetricSigningAlgType[] = [
	'ES256',
	'PS256'
];
