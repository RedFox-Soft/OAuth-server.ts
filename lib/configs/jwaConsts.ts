export const RSASignAlg = [
	'PS256',
	'PS384',
	'PS512',
	'RS256',
	'RS384',
	'RS512'
] as const;
export const ECSignAlg = ['ES256', 'ES384', 'ES512'] as const;
export const OKPSignAlg = ['EdDSA', 'Ed25519'] as const;
export const signingAlgs = [
	'HS256',
	'HS384',
	'HS512',
	...RSASignAlg,
	...ECSignAlg,
	...OKPSignAlg
] as const;
export type signingAlgValues = (typeof signingAlgs)[number];
export type asymmetricSigningAlgType = Exclude<signingAlgValues, `HS${string}`>;

export const RSAEncAlg = [
	'RSA-OAEP',
	'RSA-OAEP-256',
	'RSA-OAEP-384',
	'RSA-OAEP-512'
] as const;
export const ECOKPEncAlg = [
	'ECDH-ES',
	'ECDH-ES+A128KW',
	'ECDH-ES+A192KW',
	'ECDH-ES+A256KW'
] as const;

export const encryptionAlgs = [
	// asymmetric
	...RSAEncAlg,
	...ECOKPEncAlg,
	// symmetric
	'A128GCMKW',
	'A192GCMKW',
	'A256GCMKW',
	'A128KW',
	'A192KW',
	'A256KW',
	// direct
	'dir'
] as const;
export type encryptionAlgValues = (typeof encryptionAlgs)[number];

export type encryptionEncValues =
	| 'A128CBC-HS256'
	| 'A128GCM'
	| 'A192CBC-HS384'
	| 'A192GCM'
	| 'A256CBC-HS512'
	| 'A256GCM';
