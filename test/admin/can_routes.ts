import type {
	AddressFormChoice,
	BucketCan,
	MeCan
} from 'lib/admin/auth/can.ts';

/*
 * Which stated right governs each bucket route — the declaration the stated-rights guard (can_routes.spec.ts)
 * is generated from.
 *
 * A right is stated on the entity the path names: `:id` is the bucket, and the create route answers to the
 * caller's own rights on `GET /admin/api/me`.
 *
 * Every body below is one the route's schema admits, because a body the schema refuses is answered 422 before
 * the handler runs and so before any right is consulted. Where the right holds, each is chosen to be refused
 * by the handler's own state rules after the right was decided — a missing sub-entity, a taken slug, an
 * unconfirmed preview — so that the matrix changes nothing a later case depends on. A string value starting
 * with `:` is a placeholder the spec fills from the world it built.
 */

type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

/*
 * A right the caller states on `GET /admin/api/me`: one of its flags, or one address form listed in
 * `addressForms` (specs/101), which is a list rather than a flag because it also says which form comes first.
 */
export type MeRight =
	Exclude<keyof MeCan, 'addressForms'> | `addressForms:${AddressFormChoice}`;

interface Governed {
	readonly method: Method;
	readonly path: string;
	readonly body?: Readonly<Record<string, unknown>>;
}

export type StatedRightRoute =
	| (Governed & {
			readonly on: 'bucket';
			readonly flag: keyof BucketCan;
			/*
			 * A write to the bucket's APIs where they live in the instance's shared root namespace needs, besides
			 * the bucket's right, this right of the caller's own — as the console combines the namespace the API
			 * list states with the caller's rights on `GET /admin/api/me`.
			 */
			readonly atRoot?: MeRight;
	  })
	| (Governed & { readonly on: 'me'; readonly flag: MeRight });

const BUCKET = '/admin/api/projects/:id';

export const statedRightRoutes: readonly StatedRightRoute[] = [
	{
		on: 'me',
		flag: 'createProject',
		method: 'POST',
		path: '/admin/api/projects',
		body: { name: 'Taken', slug: ':taken-bucket-slug' }
	},
	/* The same route, asked for a hostname: an instance-level act, decided before the hostname is judged. */
	{
		on: 'me',
		flag: 'addressForms:host',
		method: 'POST',
		path: '/admin/api/projects',
		body: { name: 'Hosted', host: 'not a hostname' }
	},
	/* And asked for a subdomain: the operator's setting decides, before the name is judged (specs/101). */
	{
		on: 'me',
		flag: 'addressForms:subdomain',
		method: 'POST',
		path: '/admin/api/projects',
		body: {
			name: 'Subdomain',
			slug: ':taken-bucket-slug',
			addressForm: 'subdomain'
		}
	},

	{ on: 'bucket', flag: 'read', method: 'GET', path: BUCKET },
	{ on: 'bucket', flag: 'read', method: 'GET', path: `${BUCKET}/summary` },
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/resources`
	},
	{
		on: 'bucket',
		flag: 'editSettings',
		method: 'PATCH',
		path: BUCKET,
		body: {}
	},
	{ on: 'bucket', flag: 'delete', method: 'DELETE', path: BUCKET },
	/* The right to restore and to destroy now is the right to delete (specs/090); no bucket here is scheduled. */
	{ on: 'bucket', flag: 'delete', method: 'POST', path: `${BUCKET}/restore` },
	{ on: 'bucket', flag: 'delete', method: 'POST', path: `${BUCKET}/purge` },
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
		body: { teamId: ':destination' }
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
		method: 'GET',
		path: `${BUCKET}/users/:uid`
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
		path: `${BUCKET}/users/:uid/email`,
		body: { email: 'moved@x.io' }
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/users/:uid/verification`
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
		method: 'POST',
		path: `${BUCKET}/users/:uid/invitation`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/users/:uid/verified`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/users/:uid/sessions`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/users/:uid/sessions/:clientId/sign-out`
	},
	/* Nobody named is held by the bucket, so where the right holds each person is skipped and nothing changes. */
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/users/bulk/deactivate`,
		body: { userIds: ['absent-user'] }
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/users/bulk/activate`,
		body: { userIds: ['absent-user'] }
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/users/bulk/sign-out`,
		body: { userIds: ['absent-user'] }
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'POST',
		path: `${BUCKET}/users/bulk/delete`,
		body: { userIds: ['absent-user'] }
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
	{
		on: 'bucket',
		flag: 'read',
		method: 'GET',
		path: `${BUCKET}/federation/:providerId`
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
		flag: 'editSettings',
		method: 'POST',
		path: `${BUCKET}/federation/:providerId/move`,
		body: { direction: 'up' }
	},
	{
		on: 'bucket',
		flag: 'editSettings',
		method: 'POST',
		path: `${BUCKET}/federation/:providerId/try`
	},
	{
		on: 'bucket',
		flag: 'read',
		method: 'GET',
		path: `${BUCKET}/federation/:providerId/try/:tryRef`
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
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/provisioning-connections/:connectionId/hold`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/provisioning-connections/directories`
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
		flag: 'edit',
		method: 'DELETE',
		path: `${BUCKET}/provisioning-connections/:connectionId/credentials/:kind/previous`
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
	{
		on: 'bucket',
		flag: 'edit',
		method: 'POST',
		path: `${BUCKET}/keys/rotate`,
		body: { alg: 'ES256' }
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'POST',
		path: `${BUCKET}/keys/:kid/revoke`,
		body: { confirm: 'absent-key' }
	},

	/* A bucket's applications (specs/099): read with the bucket, changed with its `edit` right. */
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/clients`
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'POST',
		path: `${BUCKET}/clients`,
		body: {
			grantTypes: ['authorization_code'],
			redirectUris: ['https://app.example.com/cb'],
			tokenEndpointAuthMethod: 'none'
		}
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/clients/:clientId`
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'PATCH',
		path: `${BUCKET}/clients/:clientId`,
		body: {}
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'POST',
		path: `${BUCKET}/clients/:clientId/secret`
	},
	{
		on: 'bucket',
		flag: 'edit',
		method: 'DELETE',
		path: `${BUCKET}/clients/:clientId`
	},

	/* A bucket's APIs: at the shared root namespace only a super administrator declares or changes one. */
	{
		on: 'bucket',
		flag: 'edit',
		atRoot: 'instance',
		method: 'POST',
		path: `${BUCKET}/resources`,
		body: { identifier: ':resource', name: 'Probe', scopes: ['read'] }
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/resources/:resourceId`
	},
	{
		on: 'bucket',
		flag: 'manageUsers',
		method: 'GET',
		path: `${BUCKET}/resources/:resourceId/vouching`
	},
	{
		on: 'bucket',
		flag: 'edit',
		atRoot: 'instance',
		method: 'PATCH',
		path: `${BUCKET}/resources/:resourceId`,
		body: {}
	},
	{
		on: 'bucket',
		flag: 'edit',
		atRoot: 'instance',
		method: 'DELETE',
		path: `${BUCKET}/resources/:resourceId`
	}
];

/*
 * Mounted bucket routes no stated right governs, each with the reason. Empty today: every one
 * is decided by a right on the entity it names. A route belongs here only when the console has no
 * control for it to hide or show — never because the matrix found it inconvenient.
 */
export const excludedRightRoutes: readonly {
	readonly method: Method;
	readonly path: string;
	readonly reason: string;
}[] = [];

/* The routes the declaration has to cover: every one under a bucket, and the one that creates one. */
export function isGovernedSurface(method: string, path: string): boolean {
	return (
		path.startsWith('/admin/api/projects/:id') ||
		(method === 'POST' && path === '/admin/api/projects')
	);
}
