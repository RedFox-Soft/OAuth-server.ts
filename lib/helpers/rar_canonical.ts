/*
 * Structural identity for an RFC 9396 authorization detail.
 *
 * RFC 9396 §12 is explicit: "All string comparisons in an authorization_details parameter are to be
 * done as defined by [RFC8259]. No additional transformation or normalization is to be done in
 * evaluating equivalence of string values." So nothing here trims, case-folds, or Unicode-normalizes
 * a value. Sorting object members before serializing is not a string comparison and JSON member order
 * is not significant, so it is consistent with that prohibition — and it is what makes two details
 * written in a different member order the same detail.
 *
 * A key rather than a predicate, because the callers ask set questions ("is this detail already
 * granted?") on every authorization request, and a Set lookup beats pairwise deep comparison.
 */
function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) {
		// Element order in actions/locations/… is data, not member ordering: it is preserved.
		return value.map(canonicalize);
	}

	if (value !== null && typeof value === 'object') {
		const source = value as Record<string, unknown>;
		const sorted: Record<string, unknown> = {};
		for (const key of Object.keys(source).sort()) {
			sorted[key] = canonicalize(source[key]);
		}
		return sorted;
	}

	return value;
}

export function canonicalKey(detail: unknown): string {
	return JSON.stringify(canonicalize(detail)) ?? 'undefined';
}

export function canonicalKeySet(details: unknown): Set<string> {
	if (!Array.isArray(details)) {
		return new Set();
	}
	return new Set(details.map(canonicalKey));
}
