/*
 * The namespace of everything served at the root issuer (see `namespace.ts`). Declared in this leaf so
 * the stores and the schema migration can name it without reaching the adapters. `@` cannot begin a
 * bucket id, which is a generated UUID or one of the two reserved literals.
 */
export const ROOT_NAMESPACE = '@root';

/*
 * The stored key of a declaration: its namespace and its identifier. One ASCII space joins the two
 * because a canonical resource identifier cannot contain one — the URL serializer percent-encodes a
 * space in the path, query and userinfo, and no host holds one — so the join is unambiguous, and the
 * datastore's own primary key stays the single uniqueness guarantee on every backend, race-safe with no
 * new index.
 *
 * A leaf, importing nothing, because the three stores need it and the namespace module reaches the
 * adapters; a store importing that would close a cycle through the adapter index.
 */
export function declarationId(namespace: string, identifier: string): string {
	return `${namespace} ${identifier}`;
}
