import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterAll
} from 'bun:test';
import { Elysia } from 'elysia';
import { Type, type Static } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { adminApiRoutes } from 'lib/admin/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { createClient } from 'lib/admin/clients/service.ts';
import {
	getBucketStore,
	getProjectStore,
	getProtectedResourceStore,
	getProvisioningConnectionStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_PROJECT_ID,
	DEFAULT_BUCKET_ID
} from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.js';
import { AccessToken } from 'lib/models/access_token.js';
import { Client } from 'lib/models/client.js';
import { ADMIN_MCP_CLIENT_ID, MCP_RESOURCE } from 'lib/mcp/consts.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { provider as scimProvider } from '../scim/helpers.ts';
import { createAdministrator } from '../administrators.ts';
import { rpc, call as toolCall } from '../mcp/rpc.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';
import {
	excludedRightRoutes,
	isGovernedSurface,
	statedRightRoutes,
	type StatedRightRoute
} from './can_routes.ts';

/*
 * The console hides what the server would refuse and offers what it would accept, so the rights it is
 * told have to be the server's own answer. This guard holds every bucket and project route to that: for
 * each caller and each kind of bucket or project, a route answers 403 exactly when the right the server
 * stated for that caller is false. Generated from the declaration in can_routes.ts rather than written
 * out, so a route added later is held to the same rule by adding one line — and the drift check below
 * fails until somebody does.
 */

const app = new Elysia().use(adminApiRoutes);

async function request(
	method: string,
	path: string,
	cookie: string,
	body?: Readonly<Record<string, unknown>>
): Promise<{ status: number; body: unknown }> {
	const response = await app.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { 'content-type': 'application/json', cookie },
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	const json = response.headers.get('content-type')?.includes('json');
	return {
		status: response.status,
		body: json && text ? (JSON.parse(text) as unknown) : text
	};
}

const BucketCan = Type.Object({
	read: Type.Boolean(),
	manageUsers: Type.Boolean(),
	editSettings: Type.Boolean(),
	edit: Type.Boolean(),
	readActivity: Type.Boolean(),
	changeAddress: Type.Boolean(),
	move: Type.Boolean(),
	delete: Type.Boolean()
});
const ProjectCan = Type.Object({
	read: Type.Boolean(),
	edit: Type.Boolean(),
	delete: Type.Boolean(),
	manageClients: Type.Boolean(),
	declareResources: Type.Boolean(),
	assignBucket: Type.Boolean(),
	move: Type.Boolean()
});
const MeCan = Type.Object({
	createBucket: Type.Boolean(),
	createHost: Type.Boolean(),
	createProject: Type.Boolean(),
	createGroup: Type.Boolean(),
	instance: Type.Boolean()
});
const Named = Type.Object({ id: Type.String(), name: Type.String() });
const BucketRead = Type.Object({
	_id: Type.String(),
	can: BucketCan,
	blockers: Type.Object({
		usedByProjects: Type.Array(Named),
		addressable: Type.Boolean(),
		dependents: Type.Union([
			Type.Object({
				projects: Type.Number(),
				providers: Type.Number(),
				connections: Type.Number()
			}),
			Type.Null()
		]),
		accounts: Type.Union([Type.Number(), Type.Null()])
	})
});
const ProjectRead = Type.Object({
	_id: Type.String(),
	can: ProjectCan,
	blockers: Type.Object({ hasBucket: Type.Boolean() })
});
const MeRead = Type.Object({ can: MeCan });

type Rights = Readonly<Record<string, boolean>>;

const CALLERS = [
	'super administrator',
	'group owner',
	'group member',
	'member reaching it only through a project',
	'outsider'
] as const;
type Caller = (typeof CALLERS)[number];

const BUCKETS = [
	'regular',
	'administrators',
	'default',
	'not addressable',
	'unused',
	'holding accounts'
] as const;
type BucketKind = (typeof BUCKETS)[number];

const PROJECTS = [
	'without a bucket',
	'with a bucket',
	'administrators'
] as const;
type ProjectKind = (typeof PROJECTS)[number];

interface World {
	readonly cookies: Readonly<Record<Caller, string>>;
	readonly users: Readonly<Record<Caller, User>>;
	readonly buckets: Readonly<Record<BucketKind, string>>;
	readonly projects: Readonly<Record<ProjectKind, string>>;
	readonly placeholders: Readonly<Record<string, string>>;
	readonly throughProjectName: string;
	readonly bucketedName: string;
	readonly owningGroupId: string;
}

const RESOURCE = `https://can-routes-${nanoid()
	.toLowerCase()
	.replace(/[^a-z0-9]/g, '')}.example.com/api`;

async function heldClient(): Promise<string> {
	const { view } = await createClient({
		clientId: nanoid(),
		grantTypes: ['authorization_code'],
		redirectUris: ['https://app.example.com/cb'],
		tokenEndpointAuthMethod: 'none'
	});
	return view.clientId;
}

async function project(
	ownerGroupId: string,
	bucketId: string,
	clientIds: string[] = []
) {
	const id = nanoid().toLowerCase();
	return getProjectStore().create({
		name: `project ${id}`,
		slug: `p-${id}`.replace(/[^a-z0-9-]/g, ''),
		ownerGroupId,
		bucketId,
		clientIds
	});
}

/*
 * A regular bucket and one with no address, both owned by a group with an owner and a plain member; a second
 * group whose only tie to every bucket is a project pointing at it — the reserved two included; an outsider;
 * a super administrator; and a destination group the members belong to, so a move is decided by its rights
 * and not by where it was asked to go. Two more buckets of the owning group carry the state two rights depend
 * on (specs/081): one nothing uses and that holds no accounts, and one no project uses that holds an account.
 * Built fresh per route, because some routes the right admits do change what the next caller finds — the
 * unused bucket is deleted by the first caller whose right admits it, and every later caller is then refused
 * it as a bucket that does not exist, which a caller who is not a super administrator cannot tell apart.
 */
async function world(): Promise<World> {
	await ensureAdminSeed();
	const users = {
		'super administrator': await createAdministrator('super'),
		'group owner': await createAdministrator(),
		'group member': await createAdministrator(),
		'member reaching it only through a project': await createAdministrator(),
		outsider: await createAdministrator()
	} satisfies Record<Caller, User>;

	const owning = await regularGroup(
		[users['group owner']],
		[users['group member']]
	);
	const reaching = await regularGroup([
		users['member reaching it only through a project']
	]);
	const destination = await regularGroup(
		[users['group owner']],
		[users['group member'], users['member reaching it only through a project']]
	);

	const id = nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '');
	const regular = await getBucketStore().create({
		name: `regular ${id}`,
		slug: `cr-${id}`,
		ownerGroupId: owning._id
	});
	const unaddressable = await getBucketStore().create({
		name: `legacy ${id}`,
		ownerGroupId: owning._id
	});
	const unused = await getBucketStore().create({
		name: `unused ${id}`,
		slug: `cu-${id}`,
		ownerGroupId: owning._id
	});
	const holding = await getBucketStore().create({
		name: `holding ${id}`,
		slug: `ch-${id}`,
		ownerGroupId: owning._id
	});
	await getUserStore(holding._id).create(`held-${id}@x.io`, 'hash', true);

	const bucketed = await project(owning._id, regular._id, [await heldClient()]);
	const alone = await project(owning._id, DEFAULT_BUCKET_ID, [
		await heldClient()
	]);
	const throughProject = await project(reaching._id, regular._id);
	await project(reaching._id, unaddressable._id);
	await project(reaching._id, DEFAULT_BUCKET_ID);
	await project(reaching._id, ADMIN_BUCKET_ID);

	const cookies = {} as Record<Caller, string>;
	for (const caller of CALLERS)
		cookies[caller] = await cookieFor(users[caller]);

	return {
		cookies,
		users,
		buckets: {
			regular: regular._id,
			administrators: ADMIN_BUCKET_ID,
			default: DEFAULT_BUCKET_ID,
			'not addressable': unaddressable._id,
			unused: unused._id,
			'holding accounts': holding._id
		},
		projects: {
			'without a bucket': alone._id,
			'with a bucket': bucketed._id,
			administrators: ADMIN_PROJECT_ID
		},
		placeholders: {
			':destination': destination._id,
			':taken-bucket-slug': `cr-${id}`,
			':taken-project-slug': alone.slug,
			':resource': RESOURCE
		},
		throughProjectName: throughProject.name,
		bucketedName: bucketed.name,
		owningGroupId: owning._id
	};
}

/* Every sub-entity a path names is one that does not exist, so a route the right admits stops at a 404. */
const ABSENT: Readonly<Record<string, string>> = {
	uid: 'absent-user',
	gid: 'absent-group',
	providerId: 'absent-provider',
	connectionId: 'absent-connection',
	kid: 'absent-key',
	clientId: 'absent-client',
	resourceId: encodeURIComponent('https://absent.example.com/api'),
	kind: 'oauth'
};

function pathFor(route: StatedRightRoute, entityId: string): string {
	return route.path.replace(/:([A-Za-z]+)/g, (_, name: string) =>
		name === 'id' ? encodeURIComponent(entityId) : (ABSENT[name] ?? name)
	);
}

function bodyFor(
	route: StatedRightRoute,
	w: World
): Readonly<Record<string, unknown>> | undefined {
	if (!route.body) return undefined;
	return Object.fromEntries(
		Object.entries(route.body).map(([key, value]) => [
			key,
			typeof value === 'string' && value.startsWith(':')
				? (w.placeholders[value] ?? value)
				: value
		])
	);
}

const NO_RIGHTS: Rights = new Proxy({}, { get: () => false });

/*
 * What the console is told about this caller and this entity. A caller refused the read is offered
 * nothing, so every right is false for them.
 */
async function statedRights(
	route: StatedRightRoute,
	cookie: string,
	entityId: string
): Promise<Rights> {
	if (route.on === 'me') {
		return shaped(MeRead, (await request('GET', '/admin/api/me', cookie)).body)
			.can;
	}
	const read = await request(
		'GET',
		`/admin/api/${route.on === 'bucket' ? 'buckets' : 'projects'}/${encodeURIComponent(entityId)}`,
		cookie
	);
	if (read.status === 403) return NO_RIGHTS;
	return route.on === 'bucket'
		? shaped(BucketRead, read.body).can
		: shaped(ProjectRead, read.body).can;
}

function entitiesFor(route: StatedRightRoute, w: World): [string, string][] {
	if (route.on === 'bucket') return BUCKETS.map((k) => [k, w.buckets[k]]);
	if (route.on === 'project') return PROJECTS.map((k) => [k, w.projects[k]]);
	return [['the caller', '']];
}

const key = (r: { method: string; path: string }) => `${r.method} ${r.path}`;

/**
 * @proves Every bucket and project route refuses a caller with 403 exactly when the right the server
 * stated for that caller is false, every such route is governed by a declared right, and an agent is
 * stated the same rights as the console.
 */
describe('stated rights on buckets and projects', () => {
	let adminProjectBucket = ADMIN_BUCKET_ID;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'can_routes' });
		await ensureAdminSeed();
		adminProjectBucket =
			(await getProjectStore().find(ADMIN_PROJECT_ID))?.bucketId ??
			ADMIN_BUCKET_ID;
	});

	afterAll(async () => {
		/*
		 * The matrix lets a super administrator change the console's own project's bucket and declare a
		 * resource in the root namespace. Both are put back, because every spec after this one signs in
		 * through that project.
		 */
		await getProjectStore().update(ADMIN_PROJECT_ID, {
			bucketId: adminProjectBucket
		});
		await getProtectedResourceStore().destroy(ROOT_NAMESPACE, RESOURCE);
	});

	describe('declaration', () => {
		const mounted = elysia.routes
			.filter((route) => isGovernedSurface(route.method, route.path))
			.map((route) => ({ method: route.method, path: route.path }));

		it('governs every mounted bucket and project route by a stated right or a recorded exclusion', () => {
			const declared = new Set([
				...statedRightRoutes.map(key),
				...excludedRightRoutes.map(key)
			]);

			expect(mounted.length).toBeGreaterThan(0);
			expect(mounted.map(key).filter((k) => !declared.has(k))).toEqual([]);
		});

		it('declares no route the server does not serve', () => {
			const served = new Set(mounted.map(key));

			expect(
				[...statedRightRoutes, ...excludedRightRoutes]
					.map(key)
					.filter((k) => !served.has(k))
			).toEqual([]);
		});
	});

	describe('a route refuses a caller exactly when the stated right is false', () => {
		beforeEach(async () => {
			await getProjectStore().update(ADMIN_PROJECT_ID, {
				bucketId: adminProjectBucket
			});
		});

		for (const route of statedRightRoutes) {
			it(`${route.method} ${route.path} answers 403 exactly when ${route.on === 'me' ? 'the caller' : `the ${route.on}`} states ${route.flag} false`, async () => {
				const w = await world();
				const mismatches: string[] = [];
				let asked = 0;

				for (const caller of CALLERS) {
					for (const [kind, entityId] of entitiesFor(route, w)) {
						const rights = await statedRights(
							route,
							w.cookies[caller],
							entityId
						);
						const stated = rights[route.flag];
						const { status } = await request(
							route.method,
							pathFor(route, entityId),
							w.cookies[caller],
							bodyFor(route, w)
						);
						asked += 1;
						if (status === 403 ? stated : !stated) {
							mismatches.push(
								`${caller} on the ${kind} ${route.on}: answered ${String(status)} while ${route.flag} is ${String(stated)}`
							);
						} else if (status >= 500) {
							mismatches.push(
								`${caller} on the ${kind} ${route.on}: answered ${String(status)}`
							);
						}
					}
				}

				expect(asked).toBeGreaterThan(0);
				expect(mismatches).toEqual([]);
			});
		}
	});

	describe('what each caller is told', () => {
		let w: World;

		beforeAll(async () => {
			w = await world();
		});

		async function bucketAs(caller: Caller, kind: BucketKind) {
			return shaped(
				BucketRead,
				(
					await request(
						'GET',
						`/admin/api/buckets/${w.buckets[kind]}`,
						w.cookies[caller]
					)
				).body
			);
		}

		it('states the right to manage users but not to change the bucket to an administrator who reaches it only through a project', async () => {
			const { can } = await bucketAs(
				'member reaching it only through a project',
				'regular'
			);

			expect(can).toMatchObject({
				read: true,
				manageUsers: true,
				editSettings: false,
				edit: false,
				move: false,
				delete: false
			});
		});

		it('states the right to move a bucket to an owner of its group and not to a plain member', async () => {
			const owner = await bucketAs('group owner', 'regular');
			const member = await bucketAs('group member', 'regular');

			expect([owner.can.move, member.can.move]).toEqual([true, false]);
		});

		it('offers every member with an active group a new bucket, and a hostname only to a super administrator', async () => {
			const member = shaped(
				MeRead,
				(await request('GET', '/admin/api/me', w.cookies['group member'])).body
			);
			const superAdmin = shaped(
				MeRead,
				(
					await request(
						'GET',
						'/admin/api/me',
						w.cookies['super administrator']
					)
				).body
			);

			expect(member.can).toMatchObject({
				createBucket: true,
				createHost: false
			});
			expect(superAdmin.can).toMatchObject({
				createBucket: true,
				createHost: true,
				instance: true
			});
		});

		it('names the projects still using a bucket among the reasons it cannot be deleted', async () => {
			const { blockers } = await bucketAs('super administrator', 'regular');

			expect(blockers.usedByProjects.map((p) => p.name).sort()).toEqual(
				[w.bucketedName, w.throughProjectName].sort()
			);
		});

		it('never names a project the caller cannot reach among a bucket’s blockers', async () => {
			const { blockers } = await bucketAs('group owner', 'regular');

			expect(blockers.usedByProjects.map((p) => p.name)).toEqual([
				w.bucketedName
			]);
		});

		it('reports whether a bucket has an address of its own', async () => {
			const regular = await bucketAs('super administrator', 'regular');
			const legacy = await bucketAs('super administrator', 'not addressable');

			expect([
				regular.blockers.addressable,
				legacy.blockers.addressable
			]).toEqual([true, false]);
		});

		it('states the right to change an unused bucket’s address to an owner of its group and not to a plain member', async () => {
			const owner = await bucketAs('group owner', 'unused');
			const member = await bucketAs('group member', 'unused');

			expect([owner.can.changeAddress, member.can.changeAddress]).toEqual([
				true,
				false
			]);
			expect(owner.blockers.dependents).toEqual({
				projects: 0,
				providers: 0,
				connections: 0
			});
		});

		it('states the right to change the address of a bucket a project uses to a super administrator only, and tells an owner what depends on it', async () => {
			const owner = await bucketAs('group owner', 'regular');
			const superAdmin = await bucketAs('super administrator', 'regular');

			expect([owner.can.changeAddress, superAdmin.can.changeAddress]).toEqual([
				false,
				true
			]);
			/* Counted across the instance: the project another group points at it counts too. */
			expect(owner.blockers.dependents).toEqual({
				projects: 2,
				providers: 0,
				connections: 0
			});
		});

		it('states no right to an owner to change the address of a bucket an identity provider depends on', async () => {
			const bucket = await getBucketStore().create({
				name: `with provider ${nanoid()}`,
				slug: `cp-${nanoid()
					.toLowerCase()
					.replace(/[^a-z0-9]/g, '')}`,
				ownerGroupId: w.owningGroupId,
				federation: [scimProvider('corp', { enabled: false })]
			});

			const read = shaped(
				BucketRead,
				(
					await request(
						'GET',
						`/admin/api/buckets/${bucket._id}`,
						w.cookies['group owner']
					)
				).body
			);

			expect(read.can.changeAddress).toBe(false);
			expect(read.blockers.dependents?.providers).toBe(1);
		});

		it('states no right to an owner to change the address of a bucket a provisioning connection depends on', async () => {
			const bucket = await getBucketStore().create({
				name: `with connection ${nanoid()}`,
				slug: `cc-${nanoid()
					.toLowerCase()
					.replace(/[^a-z0-9]/g, '')}`,
				ownerGroupId: w.owningGroupId
			});
			await getProvisioningConnectionStore().create({
				_id: nanoid(),
				bucketId: bucket._id,
				displayName: 'Directory',
				enabled: true,
				providerId: 'gone',
				correlation: { claim: 'oid', attribute: 'externalId' },
				emailTrust: 'untrusted',
				oauthCredential: null
			});

			const read = shaped(
				BucketRead,
				(
					await request(
						'GET',
						`/admin/api/buckets/${bucket._id}`,
						w.cookies['group owner']
					)
				).body
			);

			expect(read.can.changeAddress).toBe(false);
			expect(read.blockers.dependents?.connections).toBe(1);
		});

		it('states the right to delete a bucket holding accounts to an owner of its group and not to a plain member, and tells the member how many it holds', async () => {
			const owner = await bucketAs('group owner', 'holding accounts');
			const member = await bucketAs('group member', 'holding accounts');

			expect([owner.can.delete, member.can.delete]).toEqual([true, false]);
			expect([owner.blockers.accounts, member.blockers.accounts]).toEqual([
				null,
				1
			]);
		});

		it('states the right to delete a bucket holding no accounts to a plain member of its group', async () => {
			const member = await bucketAs('group member', 'unused');

			expect(member.can.delete).toBe(true);
			expect(member.blockers.accounts).toBe(0);
		});

		it('reports a project that uses a bucket as one that moves only with it', async () => {
			const read = await request(
				'GET',
				`/admin/api/projects/${w.projects['with a bucket']}`,
				w.cookies['group owner']
			);

			expect(shaped(ProjectRead, read.body).blockers.hasBucket).toBe(true);
		});

		it('states the same rights on every row of the bucket list as on the bucket itself', async () => {
			const caller = 'super administrator';
			const rows = shaped(
				Type.Array(BucketRead),
				(await request('GET', '/admin/api/buckets', w.cookies[caller])).body
			);
			const ours = rows.filter((row) =>
				Object.values(w.buckets).includes(row._id)
			);

			expect(ours.length).toBeGreaterThan(0);
			for (const row of ours) {
				const own = shaped(
					BucketRead,
					(
						await request(
							'GET',
							`/admin/api/buckets/${row._id}`,
							w.cookies[caller]
						)
					).body
				);
				expect(row.can).toEqual(own.can);
				expect(row.blockers).toEqual(own.blockers);
			}
		});

		it('states the same rights on every row of the project list as on the project itself', async () => {
			const caller = 'group owner';
			await request('PUT', '/admin/api/scope', w.cookies[caller], {
				groupId: (await getProjectStore().find(w.projects['with a bucket']))
					?.ownerGroupId
			});
			const rows = shaped(
				Type.Array(ProjectRead),
				(await request('GET', '/admin/api/projects', w.cookies[caller])).body
			);

			expect(rows.length).toBeGreaterThan(0);
			for (const row of rows) {
				const own = shaped(
					ProjectRead,
					(
						await request(
							'GET',
							`/admin/api/projects/${row._id}`,
							w.cookies[caller]
						)
					).body
				);
				expect(row.can).toEqual(own.can);
				expect(row.blockers).toEqual(own.blockers);
			}
		});
	});

	describe('an agent', () => {
		let w: World;
		let token: string;

		beforeAll(async () => {
			ApplicationConfig['mcp.enabled'] = true;
			w = await world();
			const at = new AccessToken({
				client: await Client.find(ADMIN_MCP_CLIENT_ID),
				accountId: w.users['group owner']._id,
				scope: 'openid'
			});
			at.setAudience(MCP_RESOURCE);
			token = await at.save();
			await rpc(
				{
					jsonrpc: '2.0',
					id: 0,
					method: 'initialize',
					params: {
						protocolVersion: '2026-07-28',
						capabilities: {},
						clientInfo: { name: 'test-agent', version: '1.0.0' }
					}
				},
				token
			);
		});

		async function viaAgent(tool: string, id: string): Promise<unknown> {
			const answer = await rpc(toolCall(tool, { id }), token);
			return answer.result?.structuredContent?.result;
		}

		it('receives the same stated rights on a bucket as the console', async () => {
			const id = w.buckets.regular;
			const viaConsole = shaped(
				BucketRead,
				(
					await request(
						'GET',
						`/admin/api/buckets/${id}`,
						w.cookies['group owner']
					)
				).body
			);
			const agent: Static<typeof BucketRead> = shaped(
				BucketRead,
				await viaAgent('bucket_get', id)
			);

			expect(agent.can).toEqual(viaConsole.can);
			expect(agent.can.edit).toBe(true);
		});

		it('receives the same stated rights on a project as the console', async () => {
			const id = w.projects['without a bucket'];
			const viaConsole = shaped(
				ProjectRead,
				(
					await request(
						'GET',
						`/admin/api/projects/${id}`,
						w.cookies['group owner']
					)
				).body
			);
			const agent = shaped(ProjectRead, await viaAgent('project_get', id));

			expect(agent.can).toEqual(viaConsole.can);
			expect(agent.can.delete).toBe(true);
		});
	});
});
