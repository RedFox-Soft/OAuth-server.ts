import { describe, it, expect, beforeAll, afterAll } from 'bun:test';
import { Elysia } from 'elysia';
import { Type, type Static } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { adminApiRoutes } from 'lib/admin/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { createClient } from 'lib/admin/clients/service.ts';
import {
	getBucketStore,
	getProtectedResourceStore,
	getProvisioningConnectionStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
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
 * told have to be the server's own answer. This guard holds every bucket route to that: for each caller
 * and each kind of bucket, a route answers 403 exactly when the right the server
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
const MeCan = Type.Object({
	createBucket: Type.Boolean(),
	createHost: Type.Boolean(),
	createGroup: Type.Boolean(),
	instance: Type.Boolean()
});
const BucketRead = Type.Object({
	_id: Type.String(),
	can: BucketCan,
	blockers: Type.Object({
		addressable: Type.Boolean(),
		dependents: Type.Union([
			Type.Object({
				applications: Type.Number(),
				providers: Type.Number(),
				connections: Type.Number()
			}),
			Type.Null()
		]),
		accounts: Type.Union([Type.Number(), Type.Null()])
	})
});
const MeRead = Type.Object({ can: MeCan });
const ApiList = Type.Object({
	namespace: Type.Union([Type.Literal('bucket'), Type.Literal('root')])
});

type Rights = Readonly<Record<string, boolean>>;

const CALLERS = [
	'super administrator',
	'group owner',
	'group member',
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

interface World {
	readonly cookies: Readonly<Record<Caller, string>>;
	readonly users: Readonly<Record<Caller, User>>;
	readonly buckets: Readonly<Record<BucketKind, string>>;
	readonly placeholders: Readonly<Record<string, string>>;
	readonly owningGroupId: string;
}

const RESOURCE = `https://can-routes-${nanoid()
	.toLowerCase()
	.replace(/[^a-z0-9]/g, '')}.example.com/api`;

/* An application an administrator registered in the bucket: what keeps the bucket from being deleted. */
async function holdApplication(bucketId: string): Promise<void> {
	await createClient(bucketId, {
		clientId: nanoid(),
		grantTypes: ['authorization_code'],
		redirectUris: ['https://app.example.com/cb'],
		tokenEndpointAuthMethod: 'none'
	});
}

/*
 * A regular bucket and one with no address, both owned by a group with an owner and a plain member and each
 * holding an application; an outsider; a super administrator; and a destination group the members belong to,
 * so a move is decided by its rights and not by where it was asked to go. Two more buckets of the owning group
 * carry the state two rights depend on (specs/081): one that holds nothing at all, and one that holds an
 * account and no application.
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
		outsider: await createAdministrator()
	} satisfies Record<Caller, User>;

	const owning = await regularGroup(
		[users['group owner']],
		[users['group member']]
	);
	const destination = await regularGroup(
		[users['group owner']],
		[users['group member']]
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

	await holdApplication(regular._id);
	await holdApplication(unaddressable._id);

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
		placeholders: {
			':destination': destination._id,
			':taken-bucket-slug': `cr-${id}`,
			':resource': RESOURCE
		},
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

async function meRights(cookie: string): Promise<Rights> {
	return shaped(MeRead, (await request('GET', '/admin/api/me', cookie)).body)
		.can;
}

/*
 * Whether the console is told the caller may do what this route does, to this entity. A caller refused the
 * read is offered nothing, so every right is false for them. A write to APIs that live in the shared root
 * namespace is offered as the console offers it: on the bucket's right and the caller's own right together,
 * with the namespace read from the API list as the console reads it.
 */
async function statedRight(
	route: StatedRightRoute,
	cookie: string,
	entityId: string
): Promise<boolean> {
	if (route.on === 'me') return (await meRights(cookie))[route.flag] ?? false;
	const base = `/admin/api/buckets/${encodeURIComponent(entityId)}`;
	const read = await request('GET', base, cookie);
	const rights: Rights =
		read.status === 403 ? NO_RIGHTS : shaped(BucketRead, read.body).can;
	const bucketRight = rights[route.flag] ?? false;
	if (!bucketRight || route.atRoot === undefined) return bucketRight;
	const apis = shaped(
		ApiList,
		(await request('GET', `${base}/resources`, cookie)).body
	);
	return (
		apis.namespace === 'bucket' ||
		((await meRights(cookie))[route.atRoot] ?? false)
	);
}

function entitiesFor(route: StatedRightRoute, w: World): [string, string][] {
	if (route.on === 'bucket') return BUCKETS.map((k) => [k, w.buckets[k]]);
	return [['the caller', '']];
}

const key = (r: { method: string; path: string }) => `${r.method} ${r.path}`;

/**
 * @proves Every bucket route refuses a caller with 403 exactly when the right the server stated for that
 * caller is false, every such route is governed by a declared right, and an agent is stated the same
 * rights as the console.
 */
describe('stated rights on buckets', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'can_routes' });
		await ensureAdminSeed();
	});

	afterAll(async () => {
		/* The matrix lets a super administrator declare an API in the shared root namespace; it is put back. */
		await getProtectedResourceStore().destroy(ROOT_NAMESPACE, RESOURCE);
	});

	describe('declaration', () => {
		const mounted = elysia.routes
			.filter((route) => isGovernedSurface(route.method, route.path))
			.map((route) => ({ method: route.method, path: route.path }));

		it('governs every mounted bucket route by a stated right or a recorded exclusion', () => {
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
		for (const route of statedRightRoutes) {
			it(`${route.method} ${route.path} answers 403 exactly when ${route.on === 'me' ? 'the caller' : 'the bucket'} states ${route.flag} false${route.on === 'bucket' && route.atRoot ? ` or, at the root namespace, the caller states ${route.atRoot} false` : ''}`, async () => {
				const w = await world();
				const mismatches: string[] = [];
				let asked = 0;

				for (const caller of CALLERS) {
					for (const [kind, entityId] of entitiesFor(route, w)) {
						const stated = await statedRight(
							route,
							w.cookies[caller],
							entityId
						);
						const { status } = await request(
							route.method,
							pathFor(route, entityId),
							w.cookies[caller],
							bodyFor(route, w)
						);
						asked += 1;
						if (status === 403 ? stated : !stated) {
							mismatches.push(
								`${caller} on the ${kind} ${route.on}: answered ${String(status)} while the stated right is ${String(stated)}`
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
				applications: 0,
				providers: 0,
				connections: 0
			});
		});

		it('states the right to change the address of a bucket holding an application to a super administrator only, and tells an owner what depends on it', async () => {
			const owner = await bucketAs('group owner', 'regular');
			const superAdmin = await bucketAs('super administrator', 'regular');

			expect([owner.can.changeAddress, superAdmin.can.changeAddress]).toEqual([
				false,
				true
			]);
			expect(owner.blockers.dependents).toEqual({
				applications: 1,
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
	});
});
