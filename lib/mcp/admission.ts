import { mcpClientPermissionStore } from '../adapters/index.js';
import { pinnedBucketOf, storedBucketOf } from '../admin/auth/resolveBucket.js';
import { ADMIN_MCP_CLIENT_ID } from './consts.js';

export type McpClientRefusal = 'client_not_permitted' | 'key_proof_required';

/*
 * Whether a resolved client may hold tokens for the administrative MCP surface.
 *
 * Shared by the authorization/token resource gate (`lib/addon/resources.ts`) and the live `/mcp`
 * principal resolver (`lib/mcp/principal.ts`), so both doors enforce the same allowlist, dynamic-
 * registration ban (FR-018) and key-proof rule (FR-019b) instead of letting an unpermitted client
 * fall through to the default `redfox` bucket's sign-in page.
 *
 * Returns the internal reason on refusal (which `/mcp` emits to the event bus and never to callers)
 * or `null` when the client is admitted.
 */
export async function mcpClientRefusal(client: {
	clientId: string;
	registeredDynamically?: boolean;
	tokenEndpointAuthMethod?: string;
}): Promise<McpClientRefusal | null> {
	if (client.clientId === ADMIN_MCP_CLIENT_ID) return null;
	if (client.registeredDynamically) return 'client_not_permitted';

	/*
	 * A client pinned to a non-default project resolves to that project (`resolveBucketForRequest`
	 * rule 2), never to Administrators, so it cannot authenticate an administrator even if its id
	 * matches an allowlist entry.
	 */
	if (pinnedBucketOf(await storedBucketOf(client.clientId))) {
		return 'client_not_permitted';
	}

	const permission = await mcpClientPermissionStore.findFor(client.clientId);
	if (!permission) return 'client_not_permitted';

	/*
	 * Key proof is read off the client's declared authentication method rather than from the token,
	 * which records none. That is sufficient rather than approximate: a client declaring `none` could
	 * not have presented a key-proof assertion at the token endpoint, so its method is exactly the
	 * question being asked.
	 */
	if (
		permission.requireKeyProof &&
		client.tokenEndpointAuthMethod !== 'private_key_jwt'
	) {
		return 'key_proof_required';
	}

	return null;
}
