import { createHash } from 'node:crypto';

/*
 * The name a proxy uses for an API in its check (specs/123 research R1). An API's stored key joins its namespace
 * and its identifier with a space, which no path segment can carry, so the check names it by a digest of the
 * identifier instead: derived, never stored, the same however often the API is switched between modes, and 132
 * bits long, so no two APIs of one project share it.
 */
export function checkIdOf(identifier: string): string {
	return createHash('sha256')
		.update(identifier)
		.digest('base64url')
		.slice(0, 22);
}
