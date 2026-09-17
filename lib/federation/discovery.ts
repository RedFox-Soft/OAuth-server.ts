import {
	knownProviderByIssuer,
	type IssuerRule
} from '../consts/known_providers.js';
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

function parse(
	document: unknown,
	expectedIssuer: string,
	rule: IssuerRule | undefined
): ProviderMetadata {
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
	 *
	 * One recognised provider cannot satisfy it, and not through any fault: the documents it publishes for
	 * its multi-organisation endpoints state the issuer as a literal placeholder rather than a URL, so
	 * equality refuses it outright. Where the matched catalogue entry says its issuer is templated, the
	 * published value is therefore checked against the shape an issuer of that provider has instead.
	 *
	 * The equality rule survives for **everything else**, which is the part worth protecting: for an
	 * arbitrary upstream nobody has vouched for, a document naming a different issuer is a genuine attack
	 * signal, and relaxing the check generally to accommodate one entry would give that up.
	 */
	if (rule?.kind === 'templated') {
		if (!issuerShapeOk(metadata.issuer, rule.pattern)) {
			throw new DiscoveryError(
				'issuer_mismatch',
				`document says ${metadata.issuer}`
			);
		}
		return metadata;
	}

	if (metadata.issuer !== expectedIssuer) {
		throw new DiscoveryError(
			'issuer_mismatch',
			`document says ${metadata.issuer}`
		);
	}

	return metadata;
}

/*
 * A templated issuer is published with its parameter left as a placeholder, so it matches neither the
 * configured issuer nor the pattern a real one satisfies. Accept either: the concrete form, for a
 * single-organisation endpoint that fills it in, or the placeholder form, which is the same string with
 * something brace-wrapped where the parameter goes.
 */
function issuerShapeOk(published: string, pattern: RegExp): boolean {
	if (pattern.test(published)) return true;
	return pattern.test(published.replace(/\{[^}]+\}/, 'placeholder'));
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

	/*
	 * Resolved here rather than passed in, so every caller — the sign-in flow and the admin write alike —
	 * gets the same treatment without knowing that a templated issuer exists. That shared path is the
	 * existing guarantee that a sign-in can never run against metadata the admin write would have refused.
	 */
	const metadata = parse(
		document,
		issuer,
		knownProviderByIssuer(issuer)?.issuerRule
	);
	remember(issuer, metadata);
	return metadata;
}
