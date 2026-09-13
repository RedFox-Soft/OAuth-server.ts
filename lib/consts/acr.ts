/*
 * The Authentication Context Class References this server can report.
 *
 * The server owns the *distinctions* — the ways it can actually tell one sign-in apart from
 * another — and an operator owns the *names*. That split is the whole design: matching a requested
 * context against a satisfied one is exact string comparison (OIDC Core §5.5.1.1), so a deployment
 * whose relying parties expect `urn:mace:incommon:iap:silver` or `2` must be able to say so, while
 * nobody may invent a distinction the server cannot make and then advertise it.
 *
 * Import-free on purpose, like storage_inventory.ts: lib/configs/ reads this while building the
 * settings object, and an import reaching the adapters from here would drag a datastore into that
 * graph.
 */

/*
 * Ordered weakest to strongest. The order is documentation, not logic — nothing compares
 * distinctions for strength, because "stronger" is a claim about the deployment's own policy and
 * only its operator can make it.
 */
export const ACR_DISTINCTIONS = [
	'password',
	'multi_factor',
	'federated'
] as const;

export type AcrDistinction = (typeof ACR_DISTINCTIONS)[number];

export type AcrValues = Record<AcrDistinction, string>;

/*
 * OIDC Core §2: "An absolute URI or an RFC 6711 registered name SHOULD be used as the acr value".
 * `1`/`2` are commoner in the field and satisfy neither, so they are not the default — an operator
 * whose clients expect them renames these three and nothing else changes.
 */
export const DEFAULT_ACR_VALUES: AcrValues = {
	password: 'urn:foxauth:acr:pwd',
	multi_factor: 'urn:foxauth:acr:mfa',
	federated: 'urn:foxauth:acr:federated'
};

/*
 * OIDC Core §2 fixes the meaning of "0": the authentication did not meet ISO/IEC 29115 level 1, i.e.
 * there is no confidence the same person is there. Every session this server mints rests on a
 * password or on an upstream assertion, so no distinction may be named it — that would be a false
 * statement about an authentication that did happen.
 */
export const RESERVED_ACR_VALUE = '0';
