import { adapter } from '../../adapters/index.js';
import type { Client } from './types.ts';

/*
 * Whether an operator vouched for this client's redirect URIs, which is what RFC 9700 §4.11.2 asks an
 * authorization server to weigh before redirecting to one ("the source of the redirection URI and
 * other client data"). Not whether the client is well-behaved — nothing here can know that — but
 * whether a person who administers this server put those addresses there.
 *
 * Two kinds of client carry redirect URIs nobody here looked at:
 *
 *  - one created by dynamic client registration, which records it in a field the registrant cannot set
 *    (`registeredDynamically`, written by the registration endpoint itself);
 *  - one resolved from a metadata document, whose redirect URIs are whatever the document's host
 *    publishes. Such a client is stored nowhere, so "there is no stored record" is its definition.
 *
 * The shape of the identifier is deliberately not the test: a client an administrator created may have
 * a URL for an id, and resolution reads the store first precisely so that such a client stays theirs.
 *
 * Read on the error path only, so the one extra lookup is paid where a redirect is being decided, and
 * never by a successful response.
 */
export async function redirectUrisVouchedFor(client: Client): Promise<boolean> {
	if (client.registeredDynamically) {
		return false;
	}
	return Boolean(await adapter('Client').find(client.clientId));
}
