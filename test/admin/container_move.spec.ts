import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { Type, type TSchema, type Static } from '@sinclair/typebox';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { resourceRoutes } from 'lib/admin/resources/routes.ts';
import { scopeRoutes } from 'lib/admin/scope/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ensurePersonalGroup } from 'lib/admin/groups/personal.ts';
import {
	getBucketStore,
	getGroupStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import type { User, UserBucket } from 'lib/adapters/types.ts';
import {
	ADMIN_BUCKET_ID,
	DEFAULT_BUCKET_ID,
	SUPER_ADMINS_GROUP_ID,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { namespaceOf } from 'lib/resources/namespace.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import {
	bucketWithClients,
	cookieFor,
	regularGroup
} from './ownership_fixtures.ts';

const app = new Elysia()
	.use(resolveAdmin)
	.use(bucketRoutes)
	.use(clientRoutes)
	.use(resourceRoutes)
	.use(scopeRoutes);

async function call(
	method: string,
	path: string,
	cookie: string,
	body?: Record<string, unknown>
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

function as<T extends TSchema>(schema: T, value: unknown): Static<T> {
	return shaped(schema, value);
}

const Refusal = Type.Object({ error: Type.String(), message: Type.String() });
const GroupRef = Type.Object({
	id: Type.String(),
	kind: Type.Union([Type.String(), Type.Null()]),
	name: Type.Union([Type.String(), Type.Null()])
});
const Named = Type.Object({ id: Type.String(), name: Type.String() });
const BucketPreview = Type.Object({
	confirmationRequired: Type.Literal(true),
	from: GroupRef,
	to: GroupRef,
	project: Named,
	applications: Type.Number(),
	apis: Type.Number(),
	consequence: Type.String()
});
const BucketMoved = Type.Object({
	project: Type.Object({ id: Type.String(), ownerTeamId: Type.String() })
});
const Listed = Type.Array(Type.Object({ _id: Type.String() }));
const Applications = Type.Array(Type.Object({ clientId: Type.String() }));
const Apis = Type.Object({
	resources: Type.Array(Type.Object({ identifier: Type.String() }))
});

function admin(kind: AdminKind = 'plain'): Promise<User> {
	return createAdministrator(kind, `${kind}-${Math.random()}@x.io`);
}

const moveBucket = (
	cookie: string,
	id: string,
	body: Record<string, unknown>
) => call('PUT', `/admin/api/projects/${id}/owner`, cookie, body);

async function ownerOfBucket(id: string) {
	return (await getBucketStore().find(id))?.ownerGroupId;
}

/* An API declared in the bucket, as its Resources page would declare it. */
async function apiIn(bucket: UserBucket): Promise<string> {
	const identifier = `https://api-${bucket._id.toLowerCase()}.example.com/mcp`;
	await getProtectedResourceStore().create({
		namespace: namespaceOf(bucket),
		identifier,
		bucketId: bucket._id,
		name: 'API',
		scopes: ['read']
	});
	return identifier;
}

/*
 * Alice keeps a bucket with two applications and one API in her personal group and owns Team, where Bob
 * is a plain member. Carol belongs to Alice's... nothing: a stranger to both groups.
 */
async function world() {
	const alice = await admin();
	const bob = await admin();
	const carol = await admin();
	const personal = await ensurePersonalGroup(alice._id, alice.email);
	const team = await regularGroup([alice], [bob]);
	const { bucket, clientIds } = await bucketWithClients(personal._id, 2);
	const api = await apiIn(bucket);
	return {
		alice,
		bob,
		carol,
		personal,
		team,
		bucket,
		clientIds,
		api,
		aliceCookie: await cookieFor(alice),
		bobCookie: await cookieFor(bob),
		carolCookie: await cookieFor(carol)
	};
}

/**
 * @proves A bucket moves to another administrator group with every application and API it holds, only for
 * an owner of the group it leaves who belongs to the group it joins; every refusal changes nothing and
 * reveals nothing about what the caller cannot see.
 */
describe('moving a bucket to another group', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('gives the destination the bucket after the source’s owner confirms', async () => {
		const w = await world();

		const { status, body } = await moveBucket(w.aliceCookie, w.bucket._id, {
			teamId: w.team._id,
			confirm: true
		});

		expect(status).toBe(200);
		expect(as(BucketMoved, body).project).toEqual({
			id: w.bucket._id,
			ownerTeamId: w.team._id
		});
		expect(await ownerOfBucket(w.bucket._id)).toBe(w.team._id);
	});

	it('moves a bucket for an owner of the source who is a plain member of the destination', async () => {
		const w = await world();
		const other = await regularGroup([w.bob], [w.alice]);

		const { status } = await moveBucket(w.aliceCookie, w.bucket._id, {
			teamId: other._id,
			confirm: true
		});

		expect(status).toBe(200);
		expect(await ownerOfBucket(w.bucket._id)).toBe(other._id);
	});

	it('lists the moved bucket to the destination’s members', async () => {
		const w = await world();
		await moveBucket(w.aliceCookie, w.bucket._id, {
			teamId: w.team._id,
			confirm: true
		});
		await call('PUT', '/admin/api/scope', w.bobCookie, {
			teamId: w.team._id
		});

		const buckets = as(
			Listed,
			(await call('GET', '/admin/api/projects', w.bobCookie)).body
		);

		expect(buckets.map((b) => b._id)).toContain(w.bucket._id);
	});

	it('gives the destination’s members every application of the moved bucket', async () => {
		const w = await world();
		await moveBucket(w.aliceCookie, w.bucket._id, {
			teamId: w.team._id,
			confirm: true
		});

		const { status, body } = await call(
			'GET',
			`/admin/api/projects/${w.bucket._id}/clients`,
			w.bobCookie
		);

		expect(status).toBe(200);
		expect(
			as(Applications, body)
				.map((c) => c.clientId)
				.sort()
		).toEqual([...w.clientIds].sort());
	});

	it('gives the destination’s members every API of the moved bucket', async () => {
		const w = await world();
		await moveBucket(w.aliceCookie, w.bucket._id, {
			teamId: w.team._id,
			confirm: true
		});

		const { status, body } = await call(
			'GET',
			`/admin/api/projects/${w.bucket._id}/resources`,
			w.bobCookie
		);

		expect(status).toBe(200);
		expect(as(Apis, body).resources.map((r) => r.identifier)).toEqual([w.api]);
	});

	it('refuses a member of only the source the moved bucket as it refuses one that does not exist', async () => {
		const w = await world();
		const team2 = await regularGroup([w.carol]);
		await moveBucket(w.aliceCookie, w.bucket._id, {
			teamId: w.team._id,
			confirm: true
		});
		// Carol now shares Alice's former source group only: a team Alice moved nothing into.
		await getGroupStore().update(team2._id, {
			members: [
				{ userId: w.carol._id, role: 'owner' },
				{ userId: w.alice._id, role: 'member' }
			]
		});

		const moved = await call(
			'GET',
			`/admin/api/projects/${w.bucket._id}`,
			w.carolCookie
		);
		const missing = await call(
			'GET',
			'/admin/api/projects/no-such-bucket',
			w.carolCookie
		);

		expect(moved.status).toBe(missing.status);
		expect(as(Refusal, moved.body).message).toBe(
			as(Refusal, missing.body).message
		);
	});

	/* The source group's colleague, after its owner moved their shared bucket away. */
	async function movedAwayFromColleague() {
		const owner = await admin();
		const colleague = await admin();
		const source = await regularGroup([owner], [colleague]);
		const target = await regularGroup([owner]);
		const { bucket, clientIds } = await bucketWithClients(source._id, 1);
		await apiIn(bucket);
		await moveBucket(await cookieFor(owner), bucket._id, {
			teamId: target._id,
			confirm: true
		});
		return {
			bucket,
			clientId: clientIds[0] ?? '',
			cookie: await cookieFor(colleague)
		};
	}

	it('refuses the source’s former members the moved bucket’s applications as it refuses a bucket that does not exist', async () => {
		const { bucket, clientId, cookie } = await movedAwayFromColleague();

		const moved = await call(
			'GET',
			`/admin/api/projects/${bucket._id}/clients/${clientId}`,
			cookie
		);
		const missing = await call(
			'GET',
			`/admin/api/projects/no-such-bucket/clients/${clientId}`,
			cookie
		);

		expect(moved.status).toBe(403);
		expect(moved.status).toBe(missing.status);
		expect(as(Refusal, moved.body).message).toBe(
			as(Refusal, missing.body).message
		);
	});

	it('refuses the source’s former members the moved bucket’s APIs as it refuses a bucket that does not exist', async () => {
		const { bucket, cookie } = await movedAwayFromColleague();

		const moved = await call(
			'GET',
			`/admin/api/projects/${bucket._id}/resources`,
			cookie
		);
		const missing = await call(
			'GET',
			'/admin/api/projects/no-such-bucket/resources',
			cookie
		);

		expect(moved.status).toBe(403);
		expect(moved.status).toBe(missing.status);
		expect(as(Refusal, moved.body).message).toBe(
			as(Refusal, missing.body).message
		);
	});

	it('refuses a plain member of the source, and moves nothing', async () => {
		const w = await world();
		const { bucket } = await bucketWithClients(w.team._id, 1);
		const bobs = await ensurePersonalGroup(w.bob._id, w.bob.email);

		const { status } = await moveBucket(w.bobCookie, bucket._id, {
			teamId: bobs._id,
			confirm: true
		});

		expect(status).toBe(403);
		expect(await ownerOfBucket(bucket._id)).toBe(w.team._id);
	});

	it('refuses a destination the caller does not belong to as it refuses an unknown group', async () => {
		const w = await world();
		const strangers = await regularGroup([w.carol]);

		const foreign = await moveBucket(w.aliceCookie, w.bucket._id, {
			teamId: strangers._id,
			confirm: true
		});
		const unknown = await moveBucket(w.aliceCookie, w.bucket._id, {
			teamId: 'no-such-group',
			confirm: true
		});

		expect(foreign.status).toBe(unknown.status);
		expect(as(Refusal, foreign.body).message).toBe(
			as(Refusal, unknown.body).message
		);
		expect(await ownerOfBucket(w.bucket._id)).toBe(w.personal._id);
	});

	it('refuses the administrators’ bucket', async () => {
		const owner = await admin('super');

		const { status } = await moveBucket(
			await cookieFor(owner),
			ADMIN_BUCKET_ID,
			{
				teamId: UNASSIGNED_GROUP_ID,
				confirm: true
			}
		);

		expect(status).toBe(403);
	});

	it('refuses the default bucket every tenant shares', async () => {
		const superAdmin = await admin('super');
		const team = await regularGroup([superAdmin]);

		const { status } = await moveBucket(
			await cookieFor(superAdmin),
			DEFAULT_BUCKET_ID,
			{ teamId: team._id, confirm: true }
		);

		expect(status).toBe(403);
		expect(await ownerOfBucket(DEFAULT_BUCKET_ID)).not.toBe(team._id);
	});

	it('previews the bucket by name and counts what it holds without confirmation, and moves nothing', async () => {
		const w = await world();

		const { status, body } = await moveBucket(w.aliceCookie, w.bucket._id, {
			teamId: w.team._id
		});

		expect(status).toBe(409);
		const preview = as(BucketPreview, body);
		expect(preview.from).toEqual({
			id: w.personal._id,
			kind: 'personal',
			name: w.personal.name
		});
		expect(preview.to.id).toBe(w.team._id);
		expect(preview.project).toEqual({ id: w.bucket._id, name: w.bucket.name });
		expect(preview.applications).toBe(w.clientIds.length);
		expect(preview.apis).toBe(1);
		expect(await ownerOfBucket(w.bucket._id)).toBe(w.personal._id);
	});

	it('refuses moving into the group that already owns it', async () => {
		const w = await world();

		const { status } = await moveBucket(w.aliceCookie, w.bucket._id, {
			teamId: w.personal._id,
			confirm: true
		});

		expect(status).toBe(409);
	});

	describe('as a super administrator', () => {
		it('moves a bucket out of the System group into a regular group', async () => {
			const superAdmin = await admin('super');
			const member = await admin();
			const team = await regularGroup([member]);
			const { bucket } = await bucketWithClients(UNASSIGNED_GROUP_ID, 1);

			const { status } = await moveBucket(
				await cookieFor(superAdmin),
				bucket._id,
				{
					teamId: team._id,
					confirm: true
				}
			);

			expect(status).toBe(200);
			const listed = as(
				Listed,
				(await call('GET', '/admin/api/projects', await cookieFor(member))).body
			);
			// A plain member's console is scoped to their personal group; switching shows the team's.
			expect(listed.map((b) => b._id)).not.toContain(bucket._id);
			const cookie = await cookieFor(member);
			await call('PUT', '/admin/api/scope', cookie, { teamId: team._id });
			expect(
				as(Listed, (await call('GET', '/admin/api/projects', cookie)).body).map(
					(b) => b._id
				)
			).toContain(bucket._id);
		});

		it('moves a bucket out of an administrator’s personal group into a regular group', async () => {
			const superAdmin = await admin('super');
			const w = await world();

			const { status } = await moveBucket(
				await cookieFor(superAdmin),
				w.bucket._id,
				{ teamId: w.team._id, confirm: true }
			);

			expect(status).toBe(200);
			expect(await ownerOfBucket(w.bucket._id)).toBe(w.team._id);
		});

		it('refuses another administrator’s personal group as the destination', async () => {
			const superAdmin = await admin('super');
			const w = await world();
			const bobs = await ensurePersonalGroup(w.bob._id, w.bob.email);

			const { status, body } = await moveBucket(
				await cookieFor(superAdmin),
				w.bucket._id,
				{ teamId: bobs._id, confirm: true }
			);

			expect(status).toBe(403);
			expect(as(Refusal, body).message).toBe(
				'a personal team belongs to its administrator'
			);
		});

		it('refuses the Super administrators group as it refuses an unknown group', async () => {
			const superAdmin = await admin('super');
			const cookie = await cookieFor(superAdmin);
			const w = await world();

			const reserved = await moveBucket(cookie, w.bucket._id, {
				teamId: SUPER_ADMINS_GROUP_ID,
				confirm: true
			});
			const unknown = await moveBucket(cookie, w.bucket._id, {
				teamId: 'no-such-group',
				confirm: true
			});

			expect(reserved.status).toBe(unknown.status);
			expect(as(Refusal, reserved.body).message).toBe(
				as(Refusal, unknown.body).message
			);
		});
	});
});
