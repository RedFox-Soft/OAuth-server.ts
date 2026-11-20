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
 * The distinctions, as a list. It carries no order: which context meets which is the table below and nothing else
 * (specs/142 research R1). Comparing positions here would rank a provider sign-in above a code, and the server makes
 * no claim about how a provider's sign-in compares with its own.
 */
export const ACR_DISTINCTIONS = [
	'password',
	'multi_factor',
	'phishing_resistant',
	'federated'
] as const;

export type AcrDistinction = (typeof ACR_DISTINCTIONS)[number];

export type AcrValues = Record<AcrDistinction, string>;

/*
 * Which reached contexts meet a required one (specs/142 research R1). A sign-in with a password and a code is the
 * password and more, so it meets a request for the password context; a full passkey is two factors and resists a fake
 * sign-in page, so it meets both of those. A provider sign-in meets only the provider context: this server observed no
 * method of its own there, and how the provider's compares is not a claim it can make. The table is the only place
 * strength is stated; `lib/helpers/acr_satisfaction.ts` is the only reader.
 */
export const SATISFIED_BY: Readonly<
	Record<AcrDistinction, readonly AcrDistinction[]>
> = {
	password: ['password', 'multi_factor', 'phishing_resistant'],
	multi_factor: ['multi_factor', 'phishing_resistant'],
	phishing_resistant: ['phishing_resistant'],
	federated: ['federated']
};

/*
 * OIDC Core §2: "An absolute URI or an RFC 6711 registered name SHOULD be used as the acr value".
 * `1`/`2` are commoner in the field and satisfy neither, so they are not the default — an operator
 * whose clients expect them renames these and nothing else changes. `phr` is the registered OpenID EAP
 * ACR value for a phishing-resistant authentication, which relying-party libraries and other providers
 * already answer to, so it keeps that name rather than one of ours.
 */
export const DEFAULT_ACR_VALUES: AcrValues = {
	password: 'urn:foxauth:acr:pwd',
	multi_factor: 'urn:foxauth:acr:mfa',
	phishing_resistant: 'phr',
	federated: 'urn:foxauth:acr:federated'
};

/* The phishing-resistant name used instead of `phr` when an operator already gave `phr` to another context. */
export const PHISHING_RESISTANT_FALLBACK = 'urn:foxauth:acr:phr';

/*
 * A stored `acrValues` from before the phishing-resistant context (specs/142 research R6), given a name for it: `phr`,
 * or the fallback when `phr` is already one of the operator's names. Every other name is kept. Undefined when the map
 * already names the context, or is not a map; the migration writes the result, and startup fills it in memory only so
 * the migration gate, not a validation error, is what refuses a database that is behind.
 */
export function withPhishingResistant(
	stored: unknown
): { next: Record<string, unknown>; chosen: string } | undefined {
	if (stored === null || typeof stored !== 'object' || Array.isArray(stored)) {
		return undefined;
	}
	const map = stored as Record<string, unknown>;
	if ('phishing_resistant' in map) return undefined;
	const chosen = Object.values(map).includes(
		DEFAULT_ACR_VALUES.phishing_resistant
	)
		? PHISHING_RESISTANT_FALLBACK
		: DEFAULT_ACR_VALUES.phishing_resistant;
	return { next: { ...map, phishing_resistant: chosen }, chosen };
}

/*
 * OIDC Core §2 fixes the meaning of "0": the authentication did not meet ISO/IEC 29115 level 1, i.e.
 * there is no confidence the same person is there. Every session this server mints rests on a
 * password, a passkey or an upstream assertion, so no distinction may be named it — that would be a false
 * statement about an authentication that did happen.
 */
export const RESERVED_ACR_VALUE = '0';
