/*
 * The key that makes "one connection per federation provider" a unique index. Derived by every store on
 * every write and never accepted from a caller — the `userNameKey` rule of the user store. Bucket ids and
 * provider ids contain no `:` (nanoids and `^[a-z0-9-]{1,32}$`), so the join is unambiguous.
 */
export function providerKeyOf(bucketId: string, providerId: string): string {
	return `${bucketId}:${providerId}`;
}
