import { DISCOVERY_TTL_MS, PROVIDER_CACHE_LIMIT } from './consts.js';

/*
 * The upstream provider's published metadata: fetched, checked for self-consistency, and cached.
 *
 * Two callers share this deliberately — the sign-in flow and the admin write that validates an issuer at
 * configuration time. One fetch path means a sign-in can never run against metadata the admin write would
 * have refused.
 */

export interface ProviderMetadata {
	issuer: string;
	authorizationEndpoint: string;
	tokenEndpoint: string;
	jwksUri: string;
	/* Empty when the provider advertises none, which is not the same as "all of them". */
	signingAlgValues: string[];
	codeChallengeMethods: string[];
	tokenAuthMethods: string[];
}

/* Distinguishes "the other side is broken" from "your submitted value is wrong" for the caller. */
export type DiscoveryFailure = 'unreachable' | 'malformed' | 'issuer_mismatch';

export class DiscoveryError extends Error {
	readonly reason: DiscoveryFailure;

	constructor(reason: DiscoveryFailure, detail?: string) {
		super(`discovery failed: ${reason}${detail ? ` (${detail})` : ''}`);
		this.reason = reason;
	}
}

interface CacheEntry {
	metadata: ProviderMetadata;
	expiresAtMs: number;
}

/*
 * Bounded, because the issuer is a value an operator types into a bucket document: an unbounded map keyed
 * by it is operator-driven memory growth. Insertion-ordered eviction — a Map preserves it, and the oldest
 * entry is the one whose provider has gone longest without a sign-in.
 */
const cache = new Map<string, CacheEntry>();

function remember(issuer: string, metadata: ProviderMetadata): void {
	if (cache.size >= PROVIDER_CACHE_LIMIT && !cache.has(issuer)) {
		const oldest = cache.keys().next().value;
		if (oldest !== undefined) cache.delete(oldest);
	}
	cache.set(issuer, { metadata, expiresAtMs: Date.now() + DISCOVERY_TTL_MS });
}

/* A remote document is `unknown` until proven otherwise; narrowing it is what keeps this cast-free. */
function stringAt(source: Record<string, unknown>, key: string): string {
	const value = source[key];
	if (typeof value !== 'string' || value.length === 0) {
		throw new DiscoveryError('malformed', `missing ${key}`);
	}
	return value;
}

function stringsAt(source: Record<string, unknown>, key: string): string[] {
	const value = source[key];
	if (value === undefined) return [];
	if (!Array.isArray(value)) {
		throw new DiscoveryError('malformed', `${key} is not a list`);
	}
	return value.filter((item): item is string => typeof item === 'string');
}

function parse(document: unknown, expectedIssuer: string): ProviderMetadata {
	if (typeof document !== 'object' || document === null) {
		throw new DiscoveryError('malformed', 'not an object');
	}
	const source = document as Record<string, unknown>;

	const metadata: ProviderMetadata = {
		issuer: stringAt(source, 'issuer'),
		authorizationEndpoint: stringAt(source, 'authorization_endpoint'),
		tokenEndpoint: stringAt(source, 'token_endpoint'),
		jwksUri: stringAt(source, 'jwks_uri'),
		signingAlgValues: stringsAt(
			source,
			'id_token_signing_alg_values_supported'
		),
		codeChallengeMethods: stringsAt(source, 'code_challenge_methods_supported'),
		tokenAuthMethods: stringsAt(source, 'token_endpoint_auth_methods_supported')
	};

	/*
	 * OIDC Discovery 1.0 §4.3: the document's own issuer must equal the one used to fetch it. This is the
	 * check that catches a copy-pasted tenant URL, a redirect, or a stray trailing slash — and catching it
	 * at configuration time is why the admin write calls this too.
	 */
	if (metadata.issuer !== expectedIssuer) {
		throw new DiscoveryError(
			'issuer_mismatch',
			`document says ${metadata.issuer}`
		);
	}

	return metadata;
}

/* Discard a cached document — used by the admin write so a corrected issuer takes effect at once. */
export function forgetDiscovery(issuer: string): void {
	cache.delete(issuer);
}

export async function discover(issuer: string): Promise<ProviderMetadata> {
	const cached = cache.get(issuer);
	if (cached && cached.expiresAtMs > Date.now()) {
		return cached.metadata;
	}

	let response: Response;
	try {
		response = await fetch(
			`${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`
		);
	} catch (err) {
		throw new DiscoveryError(
			'unreachable',
			err instanceof Error ? err.message : undefined
		);
	}

	if (!response.ok) {
		throw new DiscoveryError('unreachable', `status ${response.status}`);
	}

	let document: unknown;
	try {
		document = await response.json();
	} catch {
		throw new DiscoveryError('malformed', 'body is not JSON');
	}

	const metadata = parse(document, issuer);
	remember(issuer, metadata);
	return metadata;
}
