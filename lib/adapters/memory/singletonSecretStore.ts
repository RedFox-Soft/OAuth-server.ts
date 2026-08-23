import type { SecretStoreInstance } from '../types.js';

/*
 * An in-memory singleton secret: one value per instance, which is what makes a restart observable in
 * a test — re-resolving against the same instance must return the same bytes.
 *
 * `documentName` is accepted and deliberately unused. In this adapter an instance *is* the document,
 * so two instances are already separate records and no key is needed to keep them apart; in MongoDB
 * the same name derives the `_id` that does. Taking it in both places is what lets one constructor
 * type serve both adapters, and what keeps the document's identity written at the construction site
 * rather than threaded through every call.
 *
 * `read` hands back the stored reference, so a caller's `observed` argument to `replace` is that same
 * reference and identity comparison is the correct conditional-write test here. The MongoDB
 * implementation matches on the value in a query filter for the same reason; both express "only if
 * nothing else changed it since I looked".
 */
export class SingletonSecretStore implements SecretStoreInstance {
	private secret: unknown = null;

	constructor(_documentName: string) {}

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
