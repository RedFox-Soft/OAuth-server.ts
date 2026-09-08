/*
 * The one place a resource identifier is turned into its canonical form, and the one place a
 * requested indicator is compared against a declared one.
 *
 * Both declaration and request go through `canonicalizeResourceIdentifier`, which is what makes them
 * unable to disagree: an operator who declares `HTTPS://MCP.Example.com/mcp/` and a client that asks
 * for `https://mcp.example.com/mcp` are talking about the same audience, and neither had to know the
 * other's spelling. The alternative — canonicalizing on write and comparing raw on read — is how a
 * declaration silently becomes unreachable.
 *
 * Deliberately imports nothing. It is used by the store, by the admin routes and by the token path,
 * and a dependency here would reach the adapters from all three.
 */

export type CanonicalFailure = 'not_absolute' | 'fragment';

export type CanonicalResult =
	| { readonly ok: true; readonly identifier: string }
	| { readonly ok: false; readonly reason: CanonicalFailure };

export interface CanonicalOptions {
	/*
	 * Keeps a trailing slash the owner has declared meaningful. Off by default because the MCP
	 * specification asks implementations to use the slash-free form for interoperability, and because
	 * a resource whose two spellings mean different things is a trap for every client that reaches it.
	 */
	readonly trailingSlashSignificant?: boolean;
}

/*
 * A result rather than an exception. Every caller has something specific to say about a failure —
 * the admin route answers 400 with the reason, the token path answers `invalid_target` — and none of
 * them wants a try/catch around a validator.
 */
export function canonicalizeResourceIdentifier(
	input: string,
	{ trailingSlashSignificant = false }: CanonicalOptions = {}
): CanonicalResult {
	const parsed = URL.parse(input);
	if (!parsed) return { ok: false, reason: 'not_absolute' };

	/*
	 * Checked against the raw input, not against `parsed.hash`. `new URL('https://e.ly?#')` yields an
	 * empty hash for a URL that visibly carries one, which is the same inconsistency
	 * `lib/shared/check_resource.ts` documents at its own fragment check — so the two agree by using
	 * the same test.
	 */
	if (input.includes('#')) return { ok: false, reason: 'fragment' };

	// URL parsing lower-cases the scheme and host already; naming it here so a future reader does not
	// add a redundant pass, and so the tolerance FR-006a requires is visibly satisfied by construction.
	let identifier = parsed.href;

	if (!trailingSlashSignificant && identifier.endsWith('/')) {
		identifier = identifier.slice(0, -1);
	}

	return { ok: true, identifier };
}

/*
 * Exact comparison, after both sides are canonicalized. No prefix or subpath test: one resource's
 * token must never be obtainable by naming a longer or shorter path under another, which is the
 * confused-deputy problem resource indicators exist to prevent.
 *
 * `declared` is canonicalized too, even though the store holds it in canonical form already. A
 * declaration made before a canonicalization rule changed would otherwise stop matching silently,
 * and the cost of the second pass is a URL parse on a path that already does several.
 *
 * Both sides take the *same* options, and that is the whole reason the parameter exists. Canonicalize
 * the request with the resource's own trailing-slash rule and the two spellings converge; canonicalize
 * it with the default while the resource declared the slash significant, and the slash is stripped
 * from both — which would make the declaration's own distinction unobservable, and let a request for
 * the slash-free sibling take its token.
 */
export function resourceIdentifierMatches(
	declared: string,
	requested: string,
	options: CanonicalOptions = {}
): boolean {
	const left = canonicalizeResourceIdentifier(declared, options);
	const right = canonicalizeResourceIdentifier(requested, options);
	if (!left.ok || !right.ok) return false;
	return left.identifier === right.identifier;
}
