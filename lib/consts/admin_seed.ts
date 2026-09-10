import {
	ADMIN_BUCKET_ID,
	ADMIN_CLIENT_ID,
	ADMIN_PROJECT_ID,
	UNASSIGNED_GROUP_ID
} from '../admin/consts.js';
import { ADMIN_MCP_CLIENT_ID } from '../mcp/consts.js';

/*
 * What a fresh deployment is seeded with, declared once.
 *
 * There are three seeders and there will be no fewer: `lib/admin/seed.ts` writes through the store
 * abstractions and is test-only, `database/mongodb.ts` writes raw documents because a one-shot script
 * deliberately avoids the application's module graph, and the PostgreSQL script is the third. The
 * *mechanisms* legitimately differ; the *values* never should, and until now they were written out
 * twice with a comment on each asking the next author to remember the other.
 *
 * That arrangement is exactly the drift the storage inventory was built to remove one layer down: a
 * change made to one seeder and not the other silently no-ops in production while the suite stays
 * green, because the suite runs the copy production never does.
 *
 * Values only. Nothing here writes, so each seeder keeps its own idempotency idiom — `$setOnInsert`
 * for the script, find-then-create for the store path.
 */

/*
 * The holding group for containers no administrator owns. Seeded before anything that could own a
 * container; the reserved project and bucket are given it as a formality, since both sit outside the
 * group model and every route touching them refuses before ownership is consulted.
 *
 * The name is deliberately NOT here: it is `$set` rather than `$setOnInsert` on the script path, so a
 * database seeded under an older name is renamed by the next run. Keeping a mutable field beside
 * insert-only ones would invite a caller to write it the wrong way.
 */
export const SYSTEM_GROUP_SEED = {
	kind: 'system',
	members: []
} as const;

/*
 * The reserved administrator bucket. Password login stays on and no providers are accepted: the
 * console is a relying party on this server's own issuer, and a second identity source for operators
 * is a separate decision. Both the bucket PATCH and the provider routes refuse it.
 */
export const ADMIN_BUCKET_SEED = {
	_id: ADMIN_BUCKET_ID,
	name: 'Administrators',
	ownerGroupId: UNASSIGNED_GROUP_ID,
	roles: ['super_admin', 'project_admin'],
	passwordLogin: true,
	federation: [],
	/* The reserved admin bucket never accepts self-service registration. */
	registrationOpen: false,
	emailVerificationRequired: false,
	verificationMethod: 'link'
} as const;

/*
 * The default bucket, which backs every client not assigned to a project (see resolveBucketForClient).
 * Seeded so it is manageable in the admin Buckets UI rather than existing only by implication.
 */
export const DEFAULT_BUCKET_SEED = {
	_id: 'redfox',
	name: 'Default users',
	ownerGroupId: UNASSIGNED_GROUP_ID,
	roles: [],
	passwordLogin: true,
	federation: [],
	registrationOpen: true,
	emailVerificationRequired: false,
	verificationMethod: 'link'
} as const;

export const ADMIN_PROJECT_SEED = {
	_id: ADMIN_PROJECT_ID,
	name: 'Administration',
	slug: 'admin',
	type: 'admin',
	ownerGroupId: UNASSIGNED_GROUP_ID,
	bucketId: ADMIN_BUCKET_ID,
	clientIds: [ADMIN_CLIENT_ID, ADMIN_MCP_CLIENT_ID]
} as const;

/*
 * The console's own client. Public — the console runs in a browser and has no secret to keep — and
 * consent is not required of an administrator signing in to the instance they administer.
 */
export function adminConsoleClientSeed(issuer: string) {
	return {
		clientId: ADMIN_CLIENT_ID,
		applicationType: 'web',
		grantTypes: ['authorization_code'],
		responseTypes: ['code'],
		redirectUris: [`${issuer}/admin/callback`],
		token_endpoint_auth_method: 'none',
		'consent.require': false
	};
}

/*
 * The reserved MCP agent client. Public with mandatory PKCE, so nothing secret needs distributing,
 * and it lives in the admin project because that is what routes it to the administrator bucket:
 * `resolveBucketForClient` sends a client there only if it is the reserved console client or belongs
 * to a project whose bucket is the admin bucket. A dynamically registered client falls through to the
 * default bucket and cannot authenticate an administrator at all.
 *
 * Loopback redirect URIs, which is what a local MCP client can actually receive a code on. The port is
 * unpredictable, so the standard three are registered; OAuth 2.1 allows a loopback port to vary.
 */
export const ADMIN_MCP_CLIENT_SEED = {
	clientId: ADMIN_MCP_CLIENT_ID,
	applicationType: 'native',
	grantTypes: ['authorization_code', 'refresh_token'],
	responseTypes: ['code'],
	redirectUris: [
		'http://127.0.0.1:33418/callback',
		'http://localhost:33418/callback',
		'http://127.0.0.1/callback'
	],
	token_endpoint_auth_method: 'none',
	'consent.require': true
} as const;
