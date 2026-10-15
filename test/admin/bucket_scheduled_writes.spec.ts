import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { adminApiRoutes } from 'lib/admin/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { purgeAtOf } from 'lib/consts/bucket_deletion.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';
import { statedRightRoutes } from './can_routes.ts';

/*
 * Every request goes through the admin route set the console and the agent surface both mount, so what holds
 * here holds for an agent too: its tool calls are dispatched into these same routes.
 */
const app = new Elysia().use(adminApiRoutes);

const BUCKET = '/admin/api/projects/:id';

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

const Refusal = Type.Object({ message: Type.String() });

/* Mounted write routes beneath a bucket: restore and Delete now are the two that exist for a scheduled bucket, and the deletion itself is proved where it is specified. */
const guarded = elysia.routes
	.map((route) => ({ method: route.method, path: route.path }))
	.filter(
		(route) =>
			route.method !== 'GET' &&
			route.method !== 'HEAD' &&
			(route.path === BUCKET || route.path.startsWith(`${BUCKET}/`)) &&
			route.path !== `${BUCKET}/restore` &&
			route.path !== `${BUCKET}/purge` &&
			!(route.method === 'DELETE' && route.path === BUCKET)
	);

/* Reads that name the bucket alone, so each has an answer to give for it. */
const reads = elysia.routes
	.map((route) => ({ method: route.method, path: route.path }))
	.filter(
		(route) =>
			route.method === 'GET' &&
			(route.path === BUCKET || route.path.startsWith(`${BUCKET}/`)) &&
			!route.path.slice(BUCKET.length).includes(':')
	);

/*
 * A body the route's schema admits — the one the stated-rights declaration already keeps for it — so the
 * request reaches the point where a change would be decided rather than stopping at validation.
 */
function bodyFor(method: string, path: string) {
	const declared = statedRightRoutes.find(
		(route) => route.method === method && route.path === path
	)?.body;
	if (!declared) return undefined;
	return Object.fromEntries(
		Object.entries(declared).map(([key, value]) => [
			key,
			typeof value === 'string' && value.startsWith(':') ? 'absent' : value
		])
	);
}

/* Every sub-entity a path names does not exist; `kind` is a closed set, so it names a real one. */
function pathFor(path: string, bucketId: string): string {
	return path.replace(/:([A-Za-z]+)/g, (_, name: string) =>
		name === 'id' ? bucketId : name === 'kind' ? 'oauth' : 'absent'
	);
}

async function scheduled(groupId: string): Promise<UserBucket> {
	const id = nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '');
	const bucket = await getBucketStore().create({
		name: `scheduled ${id}`,
		slug: `sw-${id}`,
		ownerGroupId: groupId
	});
	const scheduledAt = new Date();
	await getBucketStore().scheduleDeletion(bucket._id, {
		scheduledAt,
		purgeAt: purgeAtOf(scheduledAt),
		scheduledBy: { userId: 'an-administrator' }
	});
	return bucket;
}

/**
 * @proves For every mounted route that changes a bucket or anything it holds, a bucket scheduled for deletion
 * refuses the change with a message saying it must be restored first — to the console and to an agent alike —
 * while a caller who may not read the bucket is refused exactly as before and never told it is scheduled;
 * reading it keeps working.
 */
describe('a bucket scheduled for deletion, administered', () => {
	let owner: string;
	let outsider: string;
	let groupId: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
	});

	beforeEach(async () => {
		await ensureAdminSeed();
		const ownerUser = await createAdministrator();
		const group = await regularGroup([ownerUser]);
		groupId = group._id;
		owner = await cookieFor(ownerUser);
		outsider = await cookieFor(await createAdministrator());
	});

	it('guards a non-empty set of routes', () => {
		expect(guarded.length).toBeGreaterThan(0);
		expect(reads.length).toBeGreaterThan(0);
	});

	it.each(guarded.map((route) => [`${route.method} ${route.path}`, route]))(
		'refuses %s to a reader with 409, saying to restore it first',
		async (_, route) => {
			const bucket = await scheduled(groupId);

			const res = await request(
				route.method,
				pathFor(route.path, bucket._id),
				owner,
				bodyFor(route.method, route.path)
			);

			expect(res.status).toBe(409);
			expect(shaped(Refusal, res.body).message).toMatch(
				/^This project is scheduled for deletion on \d{4}-\d{2}-\d{2}\. Restore it first\.$/
			);
		}
	);

	it.each(guarded.map((route) => [`${route.method} ${route.path}`, route]))(
		'answers %s to a caller who cannot read the bucket as it did before, never with 409',
		async (_, route) => {
			const bucket = await scheduled(groupId);

			const res = await request(
				route.method,
				pathFor(route.path, bucket._id),
				outsider,
				bodyFor(route.method, route.path)
			);

			expect([403, 404]).toContain(res.status);
		}
	);

	it.each(reads.map((route) => [route.path, route]))(
		'still answers GET %s',
		async (_, route) => {
			const bucket = await scheduled(groupId);

			const res = await request('GET', pathFor(route.path, bucket._id), owner);

			expect(res.status).toBe(200);
		}
	);
});
