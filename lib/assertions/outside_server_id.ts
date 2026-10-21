import { createHash } from 'node:crypto';

/*
 * The stored key of an outside authorization server connection: its project and the outside issuer. A digest
 * rather than the two joined, because the key is also the `:serverId` of the admin routes and an issuer is a
 * URL; the datastore's primary key then stays the single guarantee of one connection per issuer per project
 * on every backend, race-safe with no extra index — the arrangement declared resources use.
 *
 * A leaf, importing nothing of ours, because the three stores need it.
 */
export function outsideServerId(bucketId: string, issuer: string): string {
	return createHash('sha256')
		.update(`${bucketId}\n${issuer}`)
		.digest('base64url')
		.slice(0, 32);
}
