/*
 * The single origin rule, shared by the admin schema and the runtime comparison. Sharing it is the
 * point: a value that could never match an incoming `Origin` header must not be storable in the
 * first place, or an operator ends up staring at a list that looks right and grants nothing.
 */

// Only the two schemes a browser sends an Origin for. `file:`, `data:` and custom app schemes all
// serialize their origin as "null", which is rejected below.
const WEB_PROTOCOLS = new Set(['http:', 'https:']);

/*
 * The canonical form of an origin: scheme + host + non-default port, lowercased, nothing else.
 * `URL.origin` already does exactly this, which is why comparing against it rejects paths, queries,
 * fragments and embedded credentials without enumerating them.
 */
export function canonicalOrigin(value: string): string | undefined {
	let url: URL;
	try {
		url = new URL(value);
	} catch {
		return undefined;
	}

	if (!WEB_PROTOCOLS.has(url.protocol)) {
		return undefined;
	}

	// Serializes to the literal "null" for opaque origins; never a value to store or match.
	if (url.origin === 'null') {
		return undefined;
	}

	return url.origin;
}

/*
 * Accepts only a bare origin. The input is lower-cased before comparison so an operator can paste
 * `https://APP.example.com` — host case is not meaningful and the browser will send it folded — but
 * anything else that `URL` normalizes away (a trailing slash, a path, a written default port) is a
 * value that would silently never match, so it is refused rather than quietly rewritten.
 */
export function isValidOrigin(value: string): boolean {
	if (typeof value !== 'string' || value.length === 0) {
		return false;
	}

	// A wildcard has no meaning here: matching is exact and there is no pattern syntax. Caught
	// explicitly because `new URL('*')` throws anyway and the message should say why, not "unparseable".
	if (value.includes('*')) {
		return false;
	}

	const canonical = canonicalOrigin(value);
	return canonical !== undefined && value.toLowerCase() === canonical;
}

/*
 * Explains a rejection in terms the operator can act on. When the value was merely non-canonical the
 * message names the form it should have been, so the fix is one edit rather than a guess.
 */
export function originRejectionMessage(value: string): string {
	const canonical =
		typeof value === 'string' ? canonicalOrigin(value) : undefined;

	if (canonical !== undefined) {
		return `invalid origin ${JSON.stringify(value)}: expected ${JSON.stringify(canonical)}`;
	}

	return `invalid origin ${JSON.stringify(value)}: expected a bare http(s) origin, e.g. "https://app.example.com"`;
}

/*
 * Normalizes a submitted list for storage: every entry canonical, order preserved, duplicates
 * collapsed. Throws on the first invalid entry so a partially valid list is never half-applied.
 */
export function normalizeOrigins(values: readonly string[]): string[] {
	const out: string[] = [];

	for (const value of values) {
		if (!isValidOrigin(value)) {
			throw new InvalidOriginError(value);
		}
		const canonical = value.toLowerCase();
		if (!out.includes(canonical)) {
			out.push(canonical);
		}
	}

	return out;
}

export class InvalidOriginError extends Error {
	readonly value: string;

	constructor(value: string) {
		super(originRejectionMessage(value));
		this.value = value;
	}
}

/*
 * The request-time decision. Exact equality against the stored canonical form — no subdomain or
 * pattern matching, ever. The incoming header is case-folded first: a browser always sends the
 * serialized (already lowercase) origin, but a non-browser caller need not, and folding cannot widen
 * the match beyond case. Writes normalize, so nothing else is re-derived per request.
 */
export function isOriginAllowed(
	origin: string,
	allowed: readonly string[] | undefined
): boolean {
	if (!allowed || allowed.length === 0) {
		return false;
	}
	return allowed.includes(origin.toLowerCase());
}
