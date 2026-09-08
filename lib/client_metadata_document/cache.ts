/*
 * How long a retrieved client description document may be reused.
 *
 * The draft asks an authorization server to respect HTTP cache headers and permits it to impose its
 * own bounds, and it forbids two things outright: an error response must never be cached, and neither
 * must a document that proved invalid or malformed. Both prohibitions matter for the same reason —
 * without them a transient failure, or one malformed document served once, would be pinned in front
 * of a working one for as long as the entry lived.
 *
 * The lower bound exists because a document with `no-store` would otherwise be fetched on every
 * authorization, turning one end-user sign-in into a chain of outbound requests. The upper bound
 * exists because a document is how a client's redirect targets are known: a host that says
 * `max-age=31536000` must not be able to make a year-old copy authoritative after they have changed
 * it.
 */

export const MIN_CACHE_SECONDS = 60;
export const MAX_CACHE_SECONDS = 60 * 60;
/* Applied when a host says nothing about caching, which most will not. */
export const DEFAULT_CACHE_SECONDS = 5 * 60;

/* Bounded so a stream of distinct identifiers cannot grow this without limit. */
const MAX_ENTRIES = 500;

interface Entry {
	readonly metadata: Record<string, unknown>;
	readonly expiresAt: number;
}

const entries = new Map<string, Entry>();

/*
 * Reads `cache-control` first and `expires` only as a fallback, which is the HTTP precedence rule.
 * `no-store` and `no-cache` are honoured as "the shortest reuse we allow" rather than as zero: a
 * document is not a private response, and treating them literally would trade a real availability
 * problem for a privacy property nobody asked for.
 */
export function reuseSecondsFor(
	cacheControl: string | null,
	expires: string | null,
	now: number = Date.now()
): number {
	const clamp = (seconds: number) =>
		Math.min(MAX_CACHE_SECONDS, Math.max(MIN_CACHE_SECONDS, seconds));

	if (cacheControl) {
		const directives = cacheControl.toLowerCase();
		if (directives.includes('no-store') || directives.includes('no-cache')) {
			return MIN_CACHE_SECONDS;
		}
		const maxAge = directives.match(/max-age\s*=\s*(\d+)/);
		if (maxAge) return clamp(Number(maxAge[1]));
	}

	if (expires) {
		const at = Date.parse(expires);
		if (Number.isFinite(at)) {
			return clamp(Math.floor((at - now) / 1000));
		}
	}

	return DEFAULT_CACHE_SECONDS;
}

export function cachedDocument(
	identifier: string,
	now: number = Date.now()
): Record<string, unknown> | undefined {
	const entry = entries.get(identifier);
	if (!entry) return undefined;
	if (entry.expiresAt <= now) {
		entries.delete(identifier);
		return undefined;
	}
	return entry.metadata;
}

/*
 * Only ever called with metadata that already passed validation, which is how the draft's "never
 * cache an invalid document" rule is kept: there is no code path that could store one. A failure is
 * not offered a store function at all, rather than being offered one and asked not to use it.
 */
export function rememberDocument(
	identifier: string,
	metadata: Record<string, unknown>,
	reuseSeconds: number,
	now: number = Date.now()
): void {
	if (entries.size >= MAX_ENTRIES && !entries.has(identifier)) {
		/*
		 * Evicts the oldest insertion, which a Map iterates first. Not an LRU: the entries are
		 * indistinguishable in value and a true LRU would need a touch on every read, on the request
		 * path, to defend against a case that only arises if 500 distinct clients are in flight at once.
		 */
		const oldest = entries.keys().next();
		if (!oldest.done) entries.delete(oldest.value);
	}
	entries.set(identifier, {
		metadata,
		expiresAt: now + reuseSeconds * 1000
	});
}

/* Test seam, and the reason the module holds no other mutable state. */
export function clearDocumentCache(): void {
	entries.clear();
}
