import { getProvisioningConnectionStore } from '../adapters/index.js';
import type { RequestBucket } from '../configs/issuer.js';
import { InvalidTarget } from '../helpers/errors.js';
import type { ResourceServerInfo } from '../helpers/resource_server.js';
import { SCIM_SCOPE } from '../consts/scim.js';
import { scimBaseUrl } from './addresses.js';

/*
 * Who may hold a token for a bucket's SCIM resource, and what a connection's client may hold at all.
 *
 * The token endpoint does not check a client's bucket (lib/actions/authorization/check_bucket.ts runs only
 * for the authorization and device flows) and a client-credentials token takes its bucket from the address
 * it was requested at. So without these rules a connection of bucket A could request a token at bucket B's
 * address, and any other client could request the SCIM audience. Both are closed here, once, and every
 * caller — the resource arm and the grant — asks this module.
 */

/*
 * Opaque, so revocation is immediate: a self-contained token would outlive a rotated or revoked credential
 * by its lifetime (specs/070 R4). Ten minutes is the client-credentials default.
 */
export function scimResourceServer(audience: string): ResourceServerInfo {
	return {
		audience,
		scope: SCIM_SCOPE,
		accessTokenFormat: 'opaque',
		accessTokenTTL: 600
	};
}

export function isScimResourceOf(
	bucket: RequestBucket,
	indicator: string
): boolean {
	const base = scimBaseUrl(bucket);
	return base !== null && indicator === base;
}

/*
 * Throws unless this client is an enabled connection of the addressed bucket asking for that bucket's SCIM
 * resource. One answer for every refusal, so the response does not tell a caller which of the conditions it
 * failed.
 */
export async function assertConnectionMayMint(
	client: { provisioningConnectionId?: string },
	bucket: RequestBucket,
	indicator: string
): Promise<void> {
	const refuse = () =>
		new InvalidTarget('the client is not permitted to access this resource');
	if (!client.provisioningConnectionId) throw refuse();
	if (!isScimResourceOf(bucket, indicator)) throw refuse();
	const connection = await getProvisioningConnectionStore().find(
		client.provisioningConnectionId
	);
	if (
		!connection ||
		connection.bucketId !== bucket._id ||
		!connection.enabled
	) {
		throw refuse();
	}
}
