import { adapter, getProjectStore } from '../../adapters/index.js';
import type { UserBucket } from '../../adapters/types.js';
import { connectionClientRecord } from '../../provisioning/client.js';
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
 * Read where a redirect is being decided after an error, and by the consent page (through
 * `clientProvenance` below), which has to say who stands behind the app it is describing.
 */
export async function redirectUrisVouchedFor(client: Client): Promise<boolean> {
	if (client.registeredDynamically) {
		return false;
	}
	/* Derived by this server from the bucket's own address: nobody but the server put it there. */
	if (client.accountPageBucketId) return true;
	return Boolean(await adapter('Client').find(client.clientId));
}

/*
 * Whether the group that owns this client's project also owns `bucket` — the one test of "these users are
 * the tenant's own". Undefined when the client is in no project, so each caller decides what that means:
 * the consent waiver honours an operator's stored flag there, and `clientProvenance` counts such a client
 * as the instance's own.
 */
export async function projectGroupOwnsBucket(
	clientId: string,
	bucket: Pick<UserBucket, 'ownerGroupId'> | null | undefined
): Promise<boolean | undefined> {
	const project = await getProjectStore().findByClientId(clientId);
	if (!project) return undefined;
	return bucket?.ownerGroupId === project.ownerGroupId;
}

export type ProvenanceTier =
	'this-organization' | 'operator-registered' | 'self-registered';

/*
 * Who stands behind a client, for the person about to sign in to it — the fact the consent page's wording
 * and warnings are chosen by.
 *
 *  - self-registered: nobody here created it — dynamic registration, or a metadata document. Tested
 *    first, and that order is the point: such a client is in no project, and "no project" alone would
 *    otherwise read as the instance's own (it is the consent waiver's reading, which is safe there only
 *    because such a client cannot switch consent off).
 *  - this-organization: created by an administrator of the group that owns the bucket being signed into,
 *    or by the instance's operator outside any project.
 *  - operator-registered: created by an administrator of this server, but of another group. In a shared
 *    bucket that is another tenant's app, and the page must not speak of it as the organization's own.
 *
 * A provisioning connection's client is synthesized rather than stored and is not self-registered; it
 * never reaches a consent page (client credentials only), but is classified correctly all the same.
 */
export async function clientProvenance(
	client: Client,
	signInBucket: Pick<UserBucket, 'ownerGroupId'> | null | undefined
): Promise<ProvenanceTier> {
	if (
		!(await redirectUrisVouchedFor(client)) &&
		!(await connectionClientRecord(client.clientId))
	) {
		return 'self-registered';
	}
	const owns = await projectGroupOwnsBucket(client.clientId, signInBucket);
	return owns === false ? 'operator-registered' : 'this-organization';
}
