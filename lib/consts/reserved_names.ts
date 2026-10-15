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
	'global-token-revocation',
	/*
	 * The default bucket's SCIM endpoint is `/scim/v2`. A bucket named `scim` would serve its own at
	 * `/scim/scim/v2` — not a collision the router gets wrong, but an address an operator would misread as
	 * the default bucket's when pasting it into a customer's directory.
	 */
	'scim',

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
 * The labels no project may take as a subdomain of the instance's host (specs/101), beyond the path names
 * above, which every slug already avoids.
 *
 * A separate list because the two protect different things. The path names keep a project from shadowing one
 * of this server's routes, so `www` is harmless as `/www`; as `www.auth.example.com` it is a name in the
 * operator's own domain under a tenant's control. These are the names an operator commonly runs beside an
 * authorization server, and the ones a phishing page would most like to borrow. Anything else the operator
 * runs goes in `projects.reservedHostnames`.
 */
export const RESERVED_SUBDOMAIN_LABELS: readonly string[] = [
	'www',
	'admin',
	'api',
	'mcp',
	'mail',
	'smtp',
	'imap',
	'pop',
	'ftp',
	'auth',
	'login',
	'sso',
	'id',
	'oauth',
	'status',
	'docs',
	'help',
	'support',
	'blog',
	'cdn',
	'static',
	'assets',
	'app',
	'dashboard',
	'console',
	'billing'
] as const;

const reservedSubdomains = new Set(RESERVED_SUBDOMAIN_LABELS);

export function isReservedSubdomainLabel(label: string): boolean {
	return reservedSubdomains.has(label);
}

/*
 * Whether a label has hyphens in its third and fourth characters — the shape RFC 5891 §4.2.3.1 reserves for
 * encoded names such as `xn--…`. A browser may show such a label as other characters, so as a subdomain it is
 * a way to look like a name it is not. Harmless as a path, which nobody renders.
 */
export function hasEncodedLabelShape(label: string): boolean {
	return label.slice(2, 4) === '--';
}

/*
 * What a bucket's slug may be, as a string so the request schema and any other consumer share one
 * declaration rather than two that agree today.
 *
 * Tighter than a plain slug (`^[a-z0-9-]+$`) in three ways, each with a reason a
 * label would not have. No leading or trailing hyphen, because this is a path segment of an
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
