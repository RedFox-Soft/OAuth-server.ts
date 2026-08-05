/*
 * The fixed quantities of the federated sign-in. Every one of them is a decision recorded in
 * specs/022-oidc-federation-login/, not a number chosen at the call site.
 */

/*
 * How long a user has to authenticate at the upstream provider. Ten minutes matches the admin console's
 * own outbound flow (lib/admin/auth/login.ts sets `maxAge: 600` on its cookie), and the two are the same
 * kind of wait: a human being typing a password into someone else's page.
 */
export const STATE_TTL_SECONDS = 600;

/*
 * Deliberately much shorter than the state it replaces. Once the assertion has verified, the only thing
 * left to happen is one same-site redirect the browser is already following — so a handoff that stayed
 * valid for ten minutes would be nine minutes of a spendable sign-in lying around for no reason.
 */
export const HANDOFF_TTL_SECONDS = 120;

/*
 * Fixed, because an upstream IdP matches `redirect_uri` by exact string and `uid` differs for every
 * interaction, so a per-interaction callback cannot be pre-registered. It is also why this route reads no
 * interaction cookie: the cookie is scoped `path: /ui/${uid}` and `sameSite: 'strict'`, and the return leg
 * from the IdP is a cross-site top-level navigation, which carries neither.
 */
export const FEDERATION_CALLBACK_PATH = '/federation/callback';

/*
 * What a read of a provider returns in place of its secret. A constant rather than a per-read
 * computation, so "the value never leaves" is a property of one line. Submitting it back *as* a secret is
 * refused rather than stored: a console that loads a masked value into a form and PATCHes the form back
 * would otherwise store the literal mask, and sign-in would then fail in a way that looks like an
 * upstream outage.
 */
export const SECRET_MASK = '********';

/* IdPs differ on which scope yields an email, so this is a default rather than a rule. */
export const DEFAULT_SCOPES = ['openid', 'email', 'profile'];

/*
 * The profile claims copied onto an account when the assertion carries them. A const, not a setting: a
 * configurable remapping table for claims nobody has asked to remap is surface with no requirement behind
 * it. `sub` is the subject and `email_verified` is the verification signal; neither is listed here
 * because neither is copied — they are read.
 *
 * Copied when an account is provisioned and when a new identity is linked, never on a later sign-in
 * through an existing link: an IdP should not silently rewrite a user's name on every login, and an
 * operator who edited a claim would watch the edit disappear.
 */
export const COPIED_CLAIMS = [
	'name',
	'given_name',
	'family_name',
	'picture',
	'locale'
] as const;

/*
 * How many upstream providers' metadata and key sets are held at once. Bounded because the URLs these
 * caches are keyed by come from a bucket document an operator edits — an unbounded map is
 * operator-driven memory growth, which is the reason spec FR-020 asks for a stated ceiling rather than
 * for "a cache".
 *
 * jose's own RemoteJWKSet supplies the TTL and the single refetch on an unknown `kid`; this is the one
 * part it does not, because it holds one instance per URL and knows nothing about how many URLs exist.
 */
export const PROVIDER_CACHE_LIMIT = 64;

/* How long fetched discovery metadata is trusted before it is fetched again. */
export const DISCOVERY_TTL_MS = 10 * 60 * 1000;
