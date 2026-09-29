import { guardedFetch, readBounded } from '../shared/egress.js';
import { canonicalizeResourceIdentifier } from './canonical.js';

/*
 * Whether a resource says, itself, that it trusts this server — its protected resource metadata (RFC
 * 9728) naming `issuer` among its `authorization_servers`.
 *
 * A declaration decides who signs in to reach a resource and which bucket's issuer its tokens carry, and
 * identifiers are unique across the instance, so declaring one is a claim on somebody's server that any
 * group member could otherwise make first. The resource settles the claim: only whoever runs it can
 * publish its metadata. Fetched through the egress boundary, since the identifier is the caller's.
 */

const TIMEOUT_MS = 5_000;
/* A metadata document is a handful of fields; anything near this bound is not one. */
const MAX_METADATA_BYTES = 64 * 1024;

export type OwnershipRefusal =
	'not_https' | 'unreachable' | 'malformed' | 'other_resource' | 'not_trusted';

/* RFC 9728 §3.1: the well-known segment goes between the host and the resource's path. */
function metadataUrl(identifier: URL): string {
	const path = identifier.pathname === '/' ? '' : identifier.pathname;
	return `${identifier.origin}/.well-known/oauth-protected-resource${path}`;
}

function withoutTrailingSlash(value: string): string {
	return value.endsWith('/') ? value.slice(0, -1) : value;
}

export async function resourceVouchesFor(
	identifier: string,
	issuer: string,
	options: { trailingSlashSignificant?: boolean } = {}
): Promise<{ ok: true } | { ok: false; reason: OwnershipRefusal }> {
	const url = new URL(identifier);
	if (url.protocol !== 'https:') return { ok: false, reason: 'not_https' };

	/*
	 * The path-inserted address first, as the RFC forms it; then the host's root document, which is
	 * where many MCP servers publish and where this project's own guide puts it. The root document still
	 * has to describe this exact resource below, so accepting it widens where the proof may live, not
	 * what it has to say.
	 */
	const candidates = [
		...new Set([
			metadataUrl(url),
			`${url.origin}/.well-known/oauth-protected-resource`
		])
	];
	let document: unknown;
	let failure: OwnershipRefusal = 'unreachable';
	for (const candidate of candidates) {
		try {
			const response = await guardedFetch(candidate, {
				headers: { accept: 'application/json' },
				timeoutMs: TIMEOUT_MS,
				httpsRedirectsOnly: true
			});
			if (!response.ok) continue;
			document = JSON.parse(await readBounded(response, MAX_METADATA_BYTES));
			break;
		} catch (err) {
			if (err instanceof SyntaxError) failure = 'malformed';
		}
	}
	if (document === undefined) return { ok: false, reason: failure };
	if (typeof document !== 'object' || document === null) {
		return { ok: false, reason: 'malformed' };
	}
	const { resource, authorization_servers: servers } = document as Record<
		string,
		unknown
	>;

	/*
	 * RFC 9728 §3.3: the document describes the resource it was fetched for, or it is not to be used.
	 * Compared canonically, the way declarations and requests are, so a spelling difference in the host
	 * does not refuse the resource's own document.
	 */
	const described =
		typeof resource === 'string'
			? canonicalizeResourceIdentifier(resource, options)
			: undefined;
	if (!described?.ok || described.identifier !== identifier) {
		return { ok: false, reason: 'other_resource' };
	}

	const trusted =
		Array.isArray(servers) &&
		servers.some(
			(server) =>
				typeof server === 'string' &&
				withoutTrailingSlash(server) === withoutTrailingSlash(issuer)
		);
	return trusted ? { ok: true } : { ok: false, reason: 'not_trusted' };
}
