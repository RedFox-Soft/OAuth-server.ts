import sectorValidate from '../../helpers/sector_validate.ts';
import { adapter } from '../../adapters/index.js';
import { type Client, type ClientRecord } from './types.ts';
import { validateClient } from './validate.ts';
import { toStored } from './projection.ts';
import { rootKeys } from '../../keys/issuer_keys.js';

/*
 * The one way a client is written, whichever surface writes it — dynamic registration, registration
 * management, the console, the agent. The sector identifier document is checked here and only here:
 * OIDC Core §8.1 places the check at registration, and a stored client is resolved without it, so a
 * client stays usable while its sector host is unreachable. The surfaces used to disagree — the
 * console stored without the check, which then ran on the next resolution instead, as a failure for
 * whoever used the client next.
 *
 * `store: false` is for a client that is never stored: one described by a metadata document, whose
 * resolution is its registration.
 */
export async function registerClient(
	record: ClientRecord,
	{ store }: { store: boolean }
): Promise<Client> {
	/*
	 * Validation checks a client's signing algorithms against the ones the root issuer can sign with,
	 * read synchronously from the mirror its key set keeps (lib/keys/issuer_keys.ts). Reading the set
	 * here — cached, so almost always free — is what keeps that mirror current on an instance where another
	 * instance promoted a key, rather than only once something here happens to sign.
	 */
	await rootKeys();
	const client = validateClient(record);

	if (client.sectorIdentifierUri !== undefined) {
		await sectorValidate(client);
	}

	if (store) {
		await adapter('Client').upsert(client.clientId, toStored(client));
	}
	return client;
}
