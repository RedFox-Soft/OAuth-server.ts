import { getProvisioningConnectionStore } from '../adapters/index.js';
import type { ProvisioningConnection } from '../adapters/types.js';
import { CONNECTION_CLIENT_PREFIX } from '../consts/scim.js';
import { ApplicationConfig } from '../configs/application.js';

/*
 * The OAuth client a connection's key or secret credential authenticates as at the token endpoint.
 *
 * Synthesized from the connection on every resolution and stored nowhere (specs/070 R2), so the
 * connection is the single source of its credential: rotating it is one write, and there is no second
 * record to keep in step, to hide from the console's client lists, or to orphan. Everything the token
 * endpoint does — `private_key_jwt` with replay protection, constant-time secret comparison, the
 * client-credentials grant — applies unchanged.
 *
 * Grant-only by construction: no redirect URIs, no response types, and `scim` as the only scope the grant
 * gives it. What it may obtain is narrowed at the grant and the resource arm (token_policy.ts): a token for its
 * own bucket's SCIM resource, and nothing else.
 */

export function connectionClientId(connectionId: string): string {
	return `${CONNECTION_CLIENT_PREFIX}${connectionId}`;
}

export function connectionIdOfClient(clientId: string): string | undefined {
	return clientId.startsWith(CONNECTION_CLIENT_PREFIX)
		? clientId.slice(CONNECTION_CLIENT_PREFIX.length)
		: undefined;
}

/* The record validation reads: base attributes canonically, recognised metadata under wire names. */
export function connectionClientMetadata(
	connection: ProvisioningConnection
): Record<string, unknown> | undefined {
	const credential = connection.oauthCredential;
	if (!credential) return undefined;
	const metadata: Record<string, unknown> = {
		clientId: connectionClientId(connection._id),
		applicationType: 'web',
		grantTypes: ['client_credentials'],
		responseTypes: [],
		redirectUris: [],
		/*
		 * No `scope` member: client metadata may name only scopes the server advertises, and `scim` is not one
		 * of the server's — it belongs to a bucket's SCIM resource. That this client gets `scim` and nothing
		 * else is enforced at the grant (lib/actions/grants/client_credentials.ts).
		 */
		client_name: connection.displayName,
		'consent.require': false,
		provisioningConnectionId: connection._id
	};
	if (credential.kind === 'key') {
		metadata.token_endpoint_auth_method = 'private_key_jwt';
		if (credential.jwks) metadata.jwks = credential.jwks;
		if (credential.jwksUri) metadata.jwks_uri = credential.jwksUri;
		if (credential.signingAlg) {
			metadata.token_endpoint_auth_signing_alg = credential.signingAlg;
		}
	} else {
		/*
		 * Registered as basic; the token endpoint accepts post as well for a client holding a digest
		 * (lib/shared/token_auth.ts), because Entra lets its administrator pick either.
		 */
		metadata.token_endpoint_auth_method = 'client_secret_basic';
		metadata.clientSecretDigest = credential.digest;
	}
	return metadata;
}

/* The metadata for a client id naming a connection, or undefined when it names none or one with no OAuth credential. */
export async function connectionClientRecord(
	clientId: string
): Promise<Record<string, unknown> | undefined> {
	const connectionId = connectionIdOfClient(clientId);
	if (!connectionId) return undefined;
	const connection = await getProvisioningConnectionStore().find(connectionId);
	if (!connection) return undefined;
	/*
	 * With secret credentials switched off (a deviation flag, scim.secretCredentials) a secret client does not
	 * exist, so its token request is `invalid_client` — exactly what an unknown client gets, and nothing that
	 * says a credential was once there. The credential is kept, so switching the flag back restores it.
	 */
	if (
		connection.oauthCredential?.kind === 'secret' &&
		!ApplicationConfig['scim.secretCredentials']
	) {
		return undefined;
	}
	return connectionClientMetadata(connection);
}
