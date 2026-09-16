/*
 * The first path segments this server uses for itself, and therefore the names no user bucket may
 * take.
 *
 * The list is long because the default bucket is addressed at the root: its endpoints are the bare
 * paths, so every one of them is a segment a named bucket could otherwise shadow. A reserved
 * namespace (`/_/…`) for the server's own surfaces was considered and does not pay — it would
 * shorten this list by two entries and leave the other fifteen exactly where they are.
 *
 * Import-free on purpose, the same reason `storage_inventory.ts` and `migrations.ts` are: this is
 * read both by the admin surface that validates a name and by the router that resolves one, and
 * neither may pull the other's dependency graph in through a shared constant.
 *
 * Adding a top-level route means adding its segment here. Nothing fails if you forget — the name is
 * simply available to a bucket, and the first operator to take it shadows the route.
 */
export const RESERVED_BUCKET_NAMES: readonly string[] = [
	// Protocol endpoints — the default bucket's, at the root
	'auth',
	'token',
	'jwks',
	'logout',
	'device',
	'par',
	'reg',
	'userinfo',
	'backchannel',

	// End-user surfaces, unconditional by design
	'ui',
	'verify-email',
	'reset-password',
	'federation',

	// Instance-wide surfaces: these belong to the server, not to a population
	'mcp',
	/*
	 * The administrative console and its management API. Reserved as a path even though the
	 * administrators *bucket* also carries `admin` as its slug — that slug never becomes a path segment,
	 * because a reserved bucket is not addressable, so the two uses of the word do not collide.
	 */
	'admin',
	'public',
	'.well-known',

	/*
	 * Not a route, but reserved all the same: it is the name the default bucket's session cookie
	 * carries, since a cookie name cannot be empty and the default bucket has no name in its address.
	 * A bucket taking it would collide with that cookie.
	 */
	'default'
] as const;

const reserved = new Set(RESERVED_BUCKET_NAMES);

export function isReservedBucketName(name: string): boolean {
	return reserved.has(name);
}

/*
 * What a bucket's slug may be, as a string so the request schema and any other consumer share one
 * declaration rather than two that agree today.
 *
 * Tighter than the project slug beside it (`^[a-z0-9-]+$`) in three ways, each with a reason a
 * project slug did not have. No leading or trailing hyphen, because this is a path segment of an
 * issuer identifier and `https://host/-` is a poor one. Bounded at 63, because unbounded is harmless
 * in a column and unpleasant in every URL, log line and token. And lowercase only rather than
 * case-normalised: URL paths are case-sensitive and issuer identifiers are compared by exact string,
 * so an operator who typed `Acme` should be told the rule rather than find their bucket at an address
 * they did not choose.
 *
 * ASCII only is what makes "two distinct slugs cannot render identically" true. Admitting Unicode
 * would admit confusables, and a confusable tenant name inside an issuer identifier is a phishing
 * primitive.
 */
export const BUCKET_SLUG_PATTERN = '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$';
export const BUCKET_SLUG_MAX_LENGTH = 63;
