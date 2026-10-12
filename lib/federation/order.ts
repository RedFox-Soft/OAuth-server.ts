import {
	KNOWN_PROVIDERS,
	knownProviderByIssuer
} from '../consts/known_providers.js';

/*
 * The order a bucket's providers appear in — on its sign-in page and in the console's table, which must
 * agree (specs/088 R10). The one function both read.
 *
 * Providers the bucket's `signInOrder` names come first, in that order; the rest follow by the rule that
 * held before an order could be set: recognised providers in the catalogue's order, then the others
 * alphabetically by id. Never connection order, which would rearrange a page end users know whenever a
 * provider is added. A bucket nobody has reordered therefore keeps exactly the order it had, and an id the
 * order names that no longer exists is skipped.
 */
export function orderProviders<T extends { id: string; issuer: string }>(
	providers: readonly T[],
	signInOrder: readonly string[] | undefined
): T[] {
	const rank = (provider: T): number => {
		const known = knownProviderByIssuer(provider.issuer);
		if (!known) return KNOWN_PROVIDERS.length;
		return KNOWN_PROVIDERS.indexOf(known);
	};
	const listed = new Map((signInOrder ?? []).map((id, index) => [id, index]));
	const position = (provider: T): number =>
		listed.get(provider.id) ?? Number.POSITIVE_INFINITY;
	/* Copied before sorting: the array belongs to the bucket document it was read from. */
	return [...providers].sort((a, b) => {
		const byOrder = position(a) - position(b);
		if (byOrder !== 0 && !Number.isNaN(byOrder)) return byOrder;
		return rank(a) - rank(b) || a.id.localeCompare(b.id);
	});
}
