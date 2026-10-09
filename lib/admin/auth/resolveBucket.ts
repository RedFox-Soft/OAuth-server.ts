import {
	adapter,
	getProjectStore,
	mcpClientPermissionStore
} from '../../adapters/index.js';
import { ADMIN_CLIENT_ID, ADMIN_BUCKET_ID } from '../consts.js';
import { findDeclaredResource } from '../../resources/registry.js';
import { namespaceOf } from '../../resources/namespace.js';
import type { RequestBucket } from '../../configs/issuer.js';
import { MCP_RESOURCE } from '../../mcp/consts.js';

/*
 * Which user bucket a request signs a user into, in order:
 *
 *   1. the reserved admin client → the admin bucket
 *   2. a client assigned to a project → that project's bucket
 *   2b. a client that registered itself at a bucket's own address → that bucket
 *   3. a request naming ONE resource declared in the addressed issuer's namespace → that resource's
 *      project's bucket
 *   4. a permitted client identity naming the administrative MCP audience → the admin bucket
 *   5. otherwise → the default 'redfox' bucket
 *
 * Rule 3 is the answer to the question `specs/024-admin-mcp-control-plane/research.md` D6 left open:
 * how a client that belongs to no project — a dynamically registered one, or one identified by a
 * document it hosts — comes to sign in the right deployment's end-users.
 *
 * D6 rejected the shape this resembles, and the difference is decisive. Its rejected version routed a
 * client to the ADMIN bucket on the strength of `resource=<issuer>/mcp`, which would have made a
 * public endpoint a way to obtain a client targeting administrator accounts. Rule 3 cannot do that:
 * `${ISSUER}/mcp` is not a declared resource — it is claimed by the built-in arm of
 * `getResourceServerInfo` and refused at declaration time — so no request can reach the admin bucket
 * through here. What rule 3 can reach is a resource an administrator declared in a project they own,
 * whose bucket is that administrator's own choice. The parameter selects among an operator's options;
 * it cannot create one. An attacker who cannot declare a resource cannot steer this.
 *
 * It chooses only among buckets that share the addressed issuer, which is what `addressed` is for. At
 * a named bucket's address the only declarations it can see are that bucket's own, so it can only
 * confirm the address; at the root it chooses among the buckets served there, where a declaration is
 * a super administrator's. Before declarations were namespaced it read every tenant's, so whoever
 * declared another tenant's MCP server first had that server's clients signed into their population.
 *
 * Rule 2 still comes first, so a client explicitly assigned to a project is never redirected elsewhere
 * by a parameter — the stronger, operator-established relationship wins.
 */
export async function resolveBucketForRequest(
	clientId: string | undefined,
	resource: string | readonly string[] | undefined,
	addressed: RequestBucket
): Promise<string> {
	if (clientId === ADMIN_CLIENT_ID) return ADMIN_BUCKET_ID;

	if (clientId) {
		const project = await getProjectStore().findByClientId(clientId);
		if (project?.bucketId) return project.bucketId;

		const registeredAt = await registeredAtBucketOf(clientId);
		if (registeredAt) return registeredAt;
	}

	const derived = await bucketForResource(resource, namespaceOf(addressed));
	if (derived) return derived;

	if (await permittedAtAdministrativePlane(clientId, resource)) {
		return ADMIN_BUCKET_ID;
	}

	return 'redfox';
}

/*
 * Rule 2b: a client that registered itself at a bucket's own address belongs to that bucket.
 *
 * Read from the stored record rather than from a resolved client, because this runs for every caller
 * with only an identifier in hand. The registration endpoint writes the field from the address and
 * nothing else (`lib/actions/registration.ts`), so a request cannot steer it — the property D6 asked of
 * every rule here. A client identified by a document it hosts has no record and so no such field.
 */
async function registeredAtBucketOf(
	clientId: string
): Promise<string | undefined> {
	const stored = await adapter('Client').find(clientId);
	const registeredAt = stored?.registeredAtBucket;
	return typeof registeredAt === 'string' && registeredAt
		? registeredAt
		: undefined;
}

/*
 * Rule 4: a client identity an operator has permitted, signing in for the administrative MCP audience.
 *
 * This one DOES route on a request parameter, which is what D6 refused — and the difference is the
 * allowlist. There, any dynamically registered client could name `${ISSUER}/mcp` and be routed to the
 * administrator bucket, so an unauthenticated endpoint became a way to obtain a client targeting
 * administrator accounts. Here the parameter only selects the surface; whether this identity may reach
 * it at all was decided in advance by a super administrator, and recorded in the audit trail. The
 * missing operator decision is exactly what D6 named as missing.
 *
 * Last, after every other rule, so it can never take a client away from a project it belongs to.
 */
async function permittedAtAdministrativePlane(
	clientId: string | undefined,
	resource: string | readonly string[] | undefined
): Promise<boolean> {
	if (!clientId) return false;

	const named = Array.isArray(resource) ? resource : [resource as string];
	if (named.length !== 1 || named[0] !== MCP_RESOURCE) return false;

	return (await mcpClientPermissionStore.findFor(clientId)) !== null;
}

/*
 * Only a single named resource derives a bucket. Two would be ambiguous — they may belong to different
 * projects, and picking one would be a guess about which set of accounts the user should be offered.
 * Falling through to the default instead is the answer that cannot be wrong in a way nobody notices.
 */
async function bucketForResource(
	resource: string | readonly string[] | undefined,
	namespace: string
): Promise<string | undefined> {
	const identifiers =
		resource === undefined
			? []
			: typeof resource === 'string'
				? [resource]
				: resource;
	if (identifiers.length !== 1) return undefined;

	/*
	 * Through the registry's own lookup, so an upper-case host, a dropped trailing slash or a significant
	 * one resolves the bucket exactly as it resolves the token. Two paths deriving different answers
	 * from one request would be a bug nobody could see from either side — which this was, while it read
	 * the slash-free spelling alone and missed every resource whose slash is significant.
	 */
	const declared = await findDeclaredResource(identifiers[0], namespace);
	if (!declared) return undefined;

	const project = await getProjectStore().find(declared.projectId);
	return project?.bucketId ?? undefined;
}
