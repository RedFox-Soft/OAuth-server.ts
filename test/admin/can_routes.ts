import type { BucketCan, MeCan, ProjectCan } from 'lib/admin/auth/can.ts';

/*
 * Which stated right governs each bucket and project route — the declaration the stated-rights guard
 * (can_routes.spec.ts) is generated from.
 *
 * A right is stated on the entity the path names: `:id` is the bucket under /buckets and the project under
 * /projects, and the two create routes answer to the caller's own rights on `GET /admin/api/me`.
 *
 * Every body below is one the route's schema admits, because a body the schema refuses is answered 422 before
 * the handler runs and so before any right is consulted. Where the right holds, each is chosen to be refused
 * by the handler's own state rules after the right was decided — a missing sub-entity, a taken slug, an
 * unconfirmed preview — so that the matrix changes nothing a later case depends on. A string value starting
 * with `:` is a placeholder the spec fills from the world it built.
 */

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

interface Governed {
	readonly method: Method;
	readonly path: string;
	readonly body?: Readonly<Record<string, unknown>>;
}

export type StatedRightRoute =
	| (Governed & { readonly on: 'bucket'; readonly flag: keyof BucketCan })
	| (Governed & { readonly on: 'project'; readonly flag: keyof ProjectCan })
	| (Governed & { readonly on: 'me'; readonly flag: keyof MeCan });

const BUCKET = '/admin/api/buckets/:id';
const PROJECT = '/admin/api/projects/:id';

export const statedRightRoutes: readonly StatedRightRoute[] = [
	{
		on: 'me',
		flag: 'createBucket',
		method: 'POST',
		path: '/admin/api/buckets',
		body: { name: 'Taken', slug: ':taken-bucket-slug' }
	},
	/* The same route, asked for a hostname: an instance-level act, decided before the hostname is judged. */
	{
		on: 'me',
		flag: 'createHost',
		method: 'POST',
		path: '/admin/api/buckets',
		body: { name: 'Hosted', host: 'not a hostname' }
	},
	{
		on: 'me',
		flag: 'createProject',
		method: 'POST',
		path: '/admin/api/projects',
		body: { name: 'Taken', slug: ':taken-project-slug' }
	},

	{ on: 'bucket', flag: 'read', method: 'GET', path: BUCKET },
	{
		on: 'bucket',
		flag: 'editSettings',
		method: 'PATCH',
		path: BUCKET,
		body: {}
	},
	{ on: 'bucket', flag: 'delete', method: 'DELETE', path: BUCKET },
	{
		on: 'bucket',
		flag: 'changeAddress',
		method: 'POST',
		path: `${BUCKET}/address`,
		body: { slug: 'can-routes-elsewhere' }
	},
	{
		on: 'bucket',
		flag: 'move',
		method: 'PUT',
		path: `${BUCKET}/owner`,
		body: { groupId: ':destination' }
	},
	{
		on: 'bucket',
		flag: 'readActivity',
		method: 'GET',
		path: `${BUCKET}/activity`
	},

	{ on: 'bucket', flag: 'manageUsers', method: 'GET', path: `${BUCKET}/users` },
	/* `sub` is derived by the server, so the account is refused after the right — and never created. */
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/users`,
		body: { email: 'held@x.io', password: 'password-1', claims: { sub: 'x' } }
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'PATCH',
		path: `${BUCKET}/users/:uid`,
		body: {}
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/users/:uid/password`,
		body: { password: 'password-1' }
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/users/:uid/lock`,
		body: { reason: 'probe' }
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/users/:uid/unlock`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/users/:uid/sign-out`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'DELETE',
		path: `${BUCKET}/users/:uid/totp`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'DELETE',
		path: `${BUCKET}/users/:uid`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/users/:uid/identities`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'DELETE',
		path: `${BUCKET}/users/:uid/identities/:providerId`
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'POST',
		path: `${BUCKET}/users/:uid/connection`,
		body: { connectionId: 'absent' }
	},

	/*
	 * A bucket's providers follow its settings rights (specs/080): on an ordinary bucket `read` and
	 * `editSettings` answer as `manageUsers` and `edit` do, and on the administrators' bucket they admit a
	 * super administrator alone, because the console's providers decide who can reach the console.
	 */
	{
		on: 'bucket',
		flag: 'read',
		method: 'GET',
		path: `${BUCKET}/federation`
	},
	{
		on: 'bucket',
		flag: 'read',
		method: 'GET',
		path: `${BUCKET}/federation/catalogue`
	},
	/* An issuer over plain http is refused after the right, so no provider is configured. */
	{
		on: 'bucket',
		flag: 'editSettings',
		method: 'POST',
		path: `${BUCKET}/federation`,
		body: { clientId: 'probe', issuer: 'http://idp.example.com' }
	},
	{
		on: 'bucket',
		flag: 'editSettings',
		method: 'PATCH',
		path: `${BUCKET}/federation/:providerId`,
		body: {}
	},
	{
		on: 'bucket',
		flag: 'editSettings',
		method: 'DELETE',
		path: `${BUCKET}/federation/:providerId`
	},

	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/provisioning-connections`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/provisioning-connections/:connectionId`
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'POST',
		path: `${BUCKET}/provisioning-connections`,
		body: { displayName: 'Probe', providerId: 'absent' }
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'PATCH',
		path: `${BUCKET}/provisioning-connections/:connectionId`,
		body: {}
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'DELETE',
		path: `${BUCKET}/provisioning-connections/:connectionId`
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'POST',
		path: `${BUCKET}/provisioning-connections/:connectionId/release`
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'POST',
		path: `${BUCKET}/provisioning-connections/:connectionId/credentials`,
		body: { kind: 'secret' }
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'DELETE',
		path: `${BUCKET}/provisioning-connections/:connectionId/credentials/:kind`
	},

	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/groups`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/groups/:gid`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/groups/:gid/members`
	},
	/* A blank name is refused after the right, so no group is created. */
	{
		on: 'bucket',
		flag: 'edit',
		method: 'POST',
		path: `${BUCKET}/groups`,
		body: { displayName: ' ' }
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'PATCH',
		path: `${BUCKET}/groups/:gid`,
		body: { displayName: 'Probe' }
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'DELETE',
		path: `${BUCKET}/groups/:gid`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/groups/:gid/members`,
		body: { userIds: ['absent'] }
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'DELETE',
		path: `${BUCKET}/groups/:gid/members/:uid`
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'POST',
		path: `${BUCKET}/groups/:gid/connection`,
		body: { connectionId: 'absent' }
	},

	{ on: 'bucket', flag: 'edit', method: 'GET', path: `${BUCKET}/keys` },
	{
		on: 'bucket',
		flag: 'edit',
		method: 'POST',
		path: `${BUCKET}/keys`,
		body: { alg: 'ES256' }
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'POST',
		path: `${BUCKET}/keys/:kid/promote`
	},
	{ on: 'bucket', flag: 'edit', method: 'DELETE', path: `${BUCKET}/keys/:kid` },

	{ on: 'project', flag: 'read', method: 'GET', path: PROJECT },
	{ on: 'project', flag: 'edit', method: 'PATCH', path: PROJECT, body: {} },
	{ on: 'project', flag: 'delete', method: 'DELETE', path: PROJECT },
	{
		on: 'project',
		flag: 'assignBucket',
		method: 'PUT',
		path: `${PROJECT}/bucket`,
		body: { bucketId: 'absent' }
	},
	/*
	 * Clearing is a project right, but it also moves the project's declarations into the shared root
	 * namespace, which only a super administrator writes — so with declarations present it is refused to
	 * anyone else whatever this flag says. The world this guard builds holds none.
	 */
	{
		on: 'project',
		flag: 'assignBucket',
		method: 'DELETE',
		path: `${PROJECT}/bucket`
	},
	{
		on: 'project',
		flag: 'move',
		method: 'PUT',
		path: `${PROJECT}/owner`,
		body: { groupId: ':destination' }
	},

	{
		on: 'project',
		flag: 'manageClients',
		method: 'GET',
		path: `${PROJECT}/clients`
	},
	{
		on: 'project',
		flag: 'manageClients',
		method: 'POST',
		path: `${PROJECT}/clients`,
		body: {
			grantTypes: ['authorization_code'],
			redirectUris: ['https://app.example.com/cb'],
			tokenEndpointAuthMethod: 'none'
		}
	},
	{
		on: 'project',
		flag: 'manageClients',
		method: 'GET',
		path: `${PROJECT}/clients/:clientId`
	},
	{
		on: 'project',
		flag: 'manageClients',
		method: 'PATCH',
		path: `${PROJECT}/clients/:clientId`,
		body: {}
	},
	{
		on: 'project',
		flag: 'manageClients',
		method: 'POST',
		path: `${PROJECT}/clients/:clientId/secret`
	},
	{
		on: 'project',
		flag: 'manageClients',
		method: 'DELETE',
		path: `${PROJECT}/clients/:clientId`
	},

	{ on: 'project', flag: 'read', method: 'GET', path: `${PROJECT}/resources` },
	{
		on: 'project',
		flag: 'declareResources',
		method: 'POST',
		path: `${PROJECT}/resources`,
		body: { identifier: ':resource', name: 'Probe', scopes: ['read'] }
	},
	{
		on: 'project',
		flag: 'read',
		method: 'GET',
		path: `${PROJECT}/resources/:resourceId`
	},
	{
		on: 'project',
		flag: 'read',
		method: 'GET',
		path: `${PROJECT}/resources/:resourceId/vouching`
	},
	{
		on: 'project',
		flag: 'declareResources',
		method: 'PATCH',
		path: `${PROJECT}/resources/:resourceId`,
		body: {}
	},
	{
		on: 'project',
		flag: 'declareResources',
		method: 'DELETE',
		path: `${PROJECT}/resources/:resourceId`
	}
];

/*
 * Mounted bucket and project routes no stated right governs, each with the reason. Empty today: every one
 * is decided by a right on the entity it names. A route belongs here only when the console has no
 * control for it to hide or show — never because the matrix found it inconvenient.
 */
export const excludedRightRoutes: readonly {
	readonly method: Method;
	readonly path: string;
	readonly reason: string;
}[] = [];

/* The routes the declaration has to cover: every one under a bucket or a project, and the two that create one. */
export function isGovernedSurface(method: string, path: string): boolean {
	return (
		path.startsWith('/admin/api/buckets/:id') ||
		path.startsWith('/admin/api/projects/:id') ||
		(method === 'POST' &&
			(path === '/admin/api/buckets' || path === '/admin/api/projects'))
	);
}
