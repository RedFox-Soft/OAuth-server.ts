import type { DPoPNonceSecretStoreInstance } from '../types.js';

/*
 * In-memory DPoP nonce secret: one value per process, which is what makes a restart observable in a
 * test — re-resolving against the same instance must return the same bytes.
 *
 * `read` hands back the stored reference, so a caller's `observed` argument to `replace` is that same
 * reference and identity comparison is the correct conditional-write test here. The MongoDB
 * implementation matches on the value in a query filter for the same reason; both express "only if
 * nothing else changed it since I looked".
 */
export class DPoPNonceSecretStore implements DPoPNonceSecretStoreInstance {
	private secret: unknown = null;

	async read(): Promise<unknown> {
		return this.secret;
	}

	async create(secret: Buffer): Promise<unknown> {
		if (this.secret === null) {
			this.secret = secret;
		}
		return this.secret;
	}

	async replace(observed: unknown, secret: Buffer): Promise<unknown> {
		// An empty store has nothing to replace: `observed === null` must not conjure a record, or a
		// caller that raced a delete would install a value nobody agreed on.
		if (this.secret !== null && this.secret === observed) {
			this.secret = secret;
		}
		return this.secret;
	}
}
