// Thin façade for the client model. The former `Client` class has been replaced
// by a TypeBox `ClientSchema`-validated plain object (built by `validateClient`
// via `Object.create(clientPrototype)`) plus small pure functions grouped by
// concern under `./client/`. There is no `Client` class for routine use
// (SC-004 — no class construction in lib/): `Client` below is a thin namespace
// function carrying the former statics (`find`/`validate`/`needsSecret`/…) and
// whose `.prototype` is the shared `clientPrototype`, so validated objects stay
// `instanceof Client` and `spyOn(Client, 'find')` keeps working.

import { adapter } from '../adapters/index.js';
import { type ClientSchemaType } from '../configs/clientSchema.ts';
import {
	clientPrototype,
	validateClient,
	assertClientValid,
	clientMetadata,
	tryFindClient
} from './client/validate.ts';
import { needsSecret } from './client/secret.ts';
import { InvalidClient } from '../helpers/errors.ts';

export type { ClientSchemaType } from '../configs/clientSchema.ts';

export {
	validateClient,
	assertClientValid,
	clientMetadata,
	tryFindClient
} from './client/validate.ts';

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

export { backchannelPing, backchannelLogout } from './client/backchannel.ts';

// Type alias kept under the historical name so `import { type Client }` sites
// continue to resolve to the validated-object type.
export type Client = ClientSchemaType;

// Namespace function grouping the former static `Client` members. Call sites import
// this directly and use `Client.find`/`Client.needsSecret`, and `value instanceof Client`
// holds for validated objects because `Client.prototype` is the shared `clientPrototype`.
export function Client(metadata: unknown) {
	return validateClient(metadata);
}

Client.prototype = clientPrototype;
Client.tryFind = tryFindClient;
// Strict lookup: resolve or throw. Default not-found error is invalid_client;
// callers whose flow needs a different code pass `{ error }`.
Client.find = async function find(id: string, options?: { error?: Error }) {
	// Delegate through the property (not the imported binding) so spyOn(Client, 'tryFind') is honored.
	const client = await Client.tryFind(id);
	if (!client) {
		throw options?.error || new InvalidClient('client not found');
	}
	return client;
};
Client.validate = assertClientValid;
Client.validateClient = validateClient;
Client.clientMetadata = clientMetadata;
Client.needsSecret = needsSecret;
Object.defineProperty(Client, 'adapter', {
	get() {
		return adapter('Client');
	}
});
