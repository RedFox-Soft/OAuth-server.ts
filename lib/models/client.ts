// The client model's one import seam. A validated client is plain, frozen data — its registration
// attributes and nothing else — and everything done with one is a function taking it first, grouped by
// concern under `./client/`. `Client` below is an object rather than a function so its lookups can be
// replaced in tests (`spyOn(Client, 'find')`).

import { tryFindClient } from './client/validate.ts';
import { type Client as ValidatedClient } from './client/types.ts';
import { InvalidClient } from '../helpers/errors.ts';

export type {
	AlwaysPresent,
	ClientData,
	ClientRecord,
	WireClient
} from './client/types.ts';

export { validateClient, tryFindClient } from './client/validate.ts';

export { registerClient } from './client/register.ts';

export { toStored, toWire, fromWire } from './client/projection.ts';

export {
	responseTypeAllowed,
	responseModeAllowed,
	grantTypeAllowed,
	redirectUriAllowed,
	postLogoutRedirectUriAllowed,
	includeSid
} from './client/checks.ts';

export {
	compareClientSecret,
	checkClientSecretExpiration,
	needsSecret
} from './client/secret.ts';

export { sectorIdentifier } from './client/sector.ts';

export { clientKeys, type ClientKeys } from './client/keys.ts';

// The validated client, under the same name as the lookup object below.
export type Client = ValidatedClient;

export const Client = {
	tryFind: tryFindClient,
	// Strict lookup: resolve or throw. Default not-found error is invalid_client;
	// callers whose flow needs a different code pass `{ error }`.
	async find(id: string, options?: { error?: Error }) {
		// Delegate through the property (not the imported binding) so spyOn(Client, 'tryFind') is honored.
		const client = await Client.tryFind(id);
		if (!client) {
			throw options?.error || new InvalidClient('client not found');
		}
		return client;
	}
};
