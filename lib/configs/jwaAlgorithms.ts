import { getAlgorithm } from 'lib/configs/verifyJWKs.js';
import { JWKS_KEYS } from './env.js';
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

const alg = getAlgorithm(JWKS_KEYS);
/*
 * idTokenSigningAlgValues
 *
 * description: JWS "alg" Algorithm values the authorization server supports to sign ID Tokens with.
 * Base on Global Keystore which will be fill startup application, Symmetric algorithm should be added manually.
 */
export const idTokenSigningAlgValues: signingAlgValues[] = [
	'HS256',
	...alg.sign
];
/*
 * userinfoSigningAlgValues
 *
 * description: JWS "alg" Algorithm values the authorization server supports to sign UserInfo responses with
 * Base on Global Keystore which will be fill startup application, Symmetric algorithm should be added manually.
 */
export const userinfoSigningAlgValues: signingAlgValues[] = [
	'HS256',
	...alg.sign
];
/*
 * introspectionSigningAlgValues
 *
 * description: JWS "alg" Algorithm values the authorization server supports to sign JWT Introspection responses with
 * Base on Global Keystore which will be fill startup application, Symmetric algorithm should be added manually.
 */
export const introspectionSigningAlgValues: signingAlgValues[] = [
	'HS256',
	...alg.sign
];
/*
 * authorizationSigningAlgValues
 *
 * description: JWS "alg" Algorithm values the authorization server supports to sign JWT Authorization Responses (`JARM`) with
 * Base on Global Keystore which will be fill startup application, Symmetric algorithm should be added manually.
 */
export const authorizationSigningAlgValues: signingAlgValues[] = [
	'HS256',
	...alg.sign
];
/*
 * requestObjectEncryptionAlgValues
 *
 * description: JWE "alg" Algorithm values the authorization server supports to receive encrypted Request Objects (`JAR`) with
 * Base on Global Keystore which will be fill startup application, Symmetric algorithm should be added manually.
 */
export const requestObjectEncryptionAlgValues: encryptionAlgValues[] = [
	...alg.enc,
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
