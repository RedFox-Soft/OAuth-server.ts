import { getProvisioningConnectionStore } from '../adapters/index.js';
import type { ProvisioningConnection } from '../adapters/types.js';
import { ApplicationConfig } from '../configs/application.js';
import type { RequestBucket } from '../configs/issuer.js';
import { SCIM_SCOPE } from '../consts/scim.js';
import { eventBus } from '../event_bus.js';
import { DEFAULT_BUCKET_ID } from '../admin/consts.js';
import { ClientCredentials } from '../models/client_credentials.js';
import { scimBaseUrl, scimMetadataUrl } from '../provisioning/addresses.js';
import { connectionIdOfClient } from '../provisioning/client.js';
import { digestOf, isStaticToken } from '../provisioning/credentials.js';
import { ScimError } from './errors.js';

/*
 * Which connection a SCIM request acts as — the only actor this surface has.
 *
 * Two credentials, told apart by the static-token prefix without a lookup: a connection's static token,
 * found by its digest; or an opaque client-credentials token, which must name this bucket's SCIM resource as
 * its audience, carry `scim`, have been issued by this bucket, and belong to a connection of it. The
 * audience and issuing-bucket checks are what keep bucket A's token out of bucket B — the token endpoint
 * does not check a client's bucket (specs/070 R4).
 *
 * Every refusal is one 401 with one body. The reason goes to the event bus, never to the caller: a caller
 * told "wrong audience" rather than "unknown token" has learned that the token exists.
 */

export type ScimRefusalReason =
	| 'no_credential'
	| 'malformed_credential'
	| 'unknown_token'
	| 'wrong_audience'
	| 'wrong_scope'
	| 'wrong_bucket'
	| 'unknown_connection'
	| 'connection_disabled'
	| 'credential_kind_disabled';

const LAST_USED_RESOLUTION_MS = 60_000;

function unauthorized(
	bucket: RequestBucket,
	reason: ScimRefusalReason
): ScimError {
	eventBus.emit('scim.auth.refused', { bucketId: bucket._id, reason });
	const metadata = scimMetadataUrl(bucket);
	return new ScimError(
		401,
		undefined,
		'a valid credential for this bucket’s SCIM endpoint is required',
		{
			'WWW-Authenticate': metadata
				? `Bearer resource_metadata="${metadata}"`
				: 'Bearer'
		}
	);
}

/*
 * `Bearer <token>`, or — for a static token only — the token with no scheme at all, which is what Okta's
 * header mode sends when its administrator pastes just the value. The prefix keeps the bare form
 * unambiguous: nothing but a static token is accepted without a scheme.
 */
function credentialOf(authorization: string | undefined): string | null {
	if (!authorization) return null;
	const value = authorization.trim();
	const match = /^Bearer\s+(\S+)$/i.exec(value);
	if (match) return match[1];
	if (!/\s/.test(value) && isStaticToken(value)) return value;
	return null;
}

async function usable(
	bucket: RequestBucket,
	connection: ProvisioningConnection | null
): Promise<ProvisioningConnection> {
	if (!connection || connection.bucketId !== bucket._id) {
		throw unauthorized(bucket, 'unknown_connection');
	}
	if (!connection.enabled) {
		throw unauthorized(bucket, 'connection_disabled');
	}
	return connection;
}

export async function resolveScimPrincipal(
	authorization: string | undefined,
	bucket: RequestBucket
): Promise<ProvisioningConnection> {
	if (!authorization) throw unauthorized(bucket, 'no_credential');
	const credential = credentialOf(authorization);
	if (!credential) throw unauthorized(bucket, 'malformed_credential');

	const store = getProvisioningConnectionStore();
	let connection: ProvisioningConnection;

	if (isStaticToken(credential)) {
		if (!ApplicationConfig['scim.staticTokens']) {
			throw unauthorized(bucket, 'credential_kind_disabled');
		}
		connection = await usable(
			bucket,
			await store.findByStaticTokenDigest(digestOf(credential))
		);
	} else {
		const token = await ClientCredentials.tryFind(credential);
		if (!token) throw unauthorized(bucket, 'unknown_token');
		const base = scimBaseUrl(bucket);
		if (base === null || token.payload.aud !== base) {
			throw unauthorized(bucket, 'wrong_audience');
		}
		if (!token.payload.scope?.split(' ').includes(SCIM_SCOPE)) {
			throw unauthorized(bucket, 'wrong_scope');
		}
		/* A token minted before buckets recorded themselves carries none, and was the default bucket's. */
		if ((token.payload.bucketId ?? DEFAULT_BUCKET_ID) !== bucket._id) {
			throw unauthorized(bucket, 'wrong_bucket');
		}
		const connectionId = connectionIdOfClient(token.payload.clientId);
		if (!connectionId) throw unauthorized(bucket, 'unknown_connection');
		connection = await usable(bucket, await store.find(connectionId));
		if (
			connection.oauthCredential?.kind === 'secret' &&
			!ApplicationConfig['scim.secretCredentials']
		) {
			throw unauthorized(bucket, 'credential_kind_disabled');
		}
		if (!connection.oauthCredential) {
			throw unauthorized(bucket, 'unknown_token');
		}
	}

	/*
	 * Bookkeeping for the console's "last used", written at most once a minute per connection so a
	 * directory's import does not turn every read into a write.
	 */
	const now = Date.now();
	if (
		!connection.lastUsedAt ||
		now - connection.lastUsedAt.getTime() >= LAST_USED_RESOLUTION_MS
	) {
		await store.touch(connection._id, new Date(now));
	}
	return connection;
}
