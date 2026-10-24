/*
 * What the IPSIE SL1 profile (`ipsieSl1.enabled`) allows, declared once and import-free so the model layer can read it.
 * The rules themselves live where each behaviour lives; lib/sl1/rules.ts names them.
 */

/*
 * IPSIE Common Requirements §3.3: "MUST use PS256, ES256, or EdDSA (using the Ed25519 variant)". `Ed25519` is RFC 9864's
 * fully specified name for that same algorithm, which this server already lists beside `EdDSA`.
 */
export const SL1_SIGNING_ALGORITHMS: ReadonlySet<string> = new Set([
	'PS256',
	'ES256',
	'EdDSA',
	'Ed25519'
]);

/*
 * The algorithm a client that registered none is signed for while the profile is on. PS256 rather than ES256: it runs on
 * the RSA keys deployments already hold, and it is what FAPI 2.0 and Keycloak's secure-signing policy default to.
 */
export const SL1_DEFAULT_SIGNING_ALGORITHM = 'PS256';

export const SL1_VIOLATIONS = [
	'http_redirect_uri',
	'response_type_none',
	'signing_algorithm',
	'client_secret_jwt',
	'certificate_bound_tokens',
	'default_algorithm'
] as const;

export type Sl1Rule = (typeof SL1_VIOLATIONS)[number];
