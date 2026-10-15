import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { createClient } from 'lib/admin/clients/service.ts';
import {
	adminAuditStore,
	getBucketStore,
	getProjectStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import { ISSUER } from 'lib/configs/env.ts';
import { ROOT_NAMESPACE } from 'lib/resources/namespace.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(projectRoutes);

async function send(
	method: 'PUT',
	path: string,
	cookie: string,
	body?: unknown
): Promise<{ status: number; body: unknown }> {
	const response = await app.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { 'content-type': 'application/json', cookie },
			body: body === undefined ? undefined : JSON.stringify(body)
		})
	);
	return { status: response.status, body: await response.json() };
}

const Side = Type.Object({
	bucketId: Type.String(),
	name: Type.String(),
	issuer: Type.Union([Type.String(), Type.Null()])
});

const Preview = Type.Object({
	confirmationRequired: Type.Literal(true),
	from: Side,
	to: Side,
	applications: Type.Array(
		Type.Object({
			clientId: Type.String(),
			name: Type.Union([Type.String(), Type.Null()])
		})
	),
	resources: Type.Array(
		Type.Object({ identifier: Type.String(), name: Type.String() })
	),
	conflicts: Type.Array(Type.String()),
	rootRefused: Type.Boolean(),
	blocked: Type.Boolean(),
	consequence: Type.String(),
	expect: Type.Object({ applications: Type.Number(), resources: Type.Number() })
});

const Refusal = Type.Object({ message: Type.String() });

function slug(prefix: string): string {
	return `${prefix}-${nanoid()
		.toLowerCase()
		.replace(/[^a-z0-9]/g, '')
		.slice(0, 10)}`;
}

async function application(name: string): Promise<string> {
	const { view } = await createClient({
		clientId: nanoid(),
		clientName: name,
		grantTypes: ['authorization_code'],
		redirectUris: ['https://app.example.com/cb'],
		tokenEndpointAuthMethod: 'none'
	});
	return view.clientId;
}

async function declare(
	namespace: string,
	projectId: string,
	identifier: string
) {
	await getProtectedResourceStore().create({
		namespace,
		identifier,
		projectId,
		name: `Resource ${identifier}`,
		scopes: ['read']
	});
}

/*
 * A team owning two addressed buckets and a project in the first, with two applications and one
 * declaration in the first bucket's namespace.
 */
async function world() {
	const owner = await createAdministrator('plain');
	const team = await regularGroup([owner]);
	const fromSlug = slug('from');
	const toSlug = slug('to');
	const from = await getBucketStore().create({
		name: 'Old customers',
		slug: fromSlug,
		ownerGroupId: team._id
	});
	const to = await getBucketStore().create({
		name: 'New customers',
		slug: toSlug,
		ownerGroupId: team._id
	});
	const project = await getProjectStore().create({
		name: 'Shop',
		slug: slug('shop'),
		ownerGroupId: team._id,
		bucketId: from._id,
		clientIds: [await application('Zeta app'), await application('Alpha app')]
	});
	const identifier = `https://${slug('api')}.example.com/`;
	await declare(from._id, project._id, identifier);
	return {
		owner,
		team,
		from,
		to,
		fromSlug,
		toSlug,
		project,
		identifier,
		cookie: await cookieFor(owner)
	};
}

async function trailOf(projectId: string): Promise<number> {
	return (await adminAuditStore.list({ targetId: projectId })).total;
}

/**
 * @proves Changing a project's bucket first names every application whose issuer changes, both issuers and
 * every declaration that moves or collides, and applies only when confirmed with the counts that were shown —
 * by a caller who could make the change, and with nothing recorded until then.
 */
describe("changing a project's bucket", () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('answers with a preview naming each application, both issuers and the moving declaration, and changes nothing', async () => {
		const w = await world();

		const res = await send(
			'PUT',
			`/admin/api/projects/${w.project._id}/bucket`,
			w.cookie,
			{ bucketId: w.to._id }
		);

		expect(res.status).toBe(409);
		const preview = shaped(Preview, res.body);
		expect(preview.from).toEqual({
			bucketId: w.from._id,
			name: 'Old customers',
			issuer: `${ISSUER}/${w.fromSlug}`
		});
		expect(preview.to).toEqual({
			bucketId: w.to._id,
			name: 'New customers',
			issuer: `${ISSUER}/${w.toSlug}`
		});
		expect(preview.applications.map((a) => a.name)).toEqual([
			'Alpha app',
			'Zeta app'
		]);
		expect(preview.resources).toEqual([
			{ identifier: w.identifier, name: `Resource ${w.identifier}` }
		]);
		expect(preview.blocked).toBe(false);
		expect(preview.consequence).toContain('sign in again');
		expect(preview.expect).toEqual({ applications: 2, resources: 1 });
		expect((await getProjectStore().find(w.project._id))?.bucketId).toBe(
			w.from._id
		);
		expect(
			(await getProtectedResourceStore().find(w.from._id, w.identifier))
				?.projectId
		).toBe(w.project._id);
	});

	it('answers with a fresh preview, and changes nothing, when an application arrived after the one confirmed', async () => {
		const w = await world();
		await getProjectStore().update(w.project._id, {
			clientIds: [...w.project.clientIds, await application('Late app')]
		});

		const res = await send(
			'PUT',
			`/admin/api/projects/${w.project._id}/bucket`,
			w.cookie,
			{
				bucketId: w.to._id,
				confirm: true,
				expect: { applications: 2, resources: 1 }
			}
		);

		expect(res.status).toBe(409);
		expect(shaped(Preview, res.body).expect).toEqual({
			applications: 3,
			resources: 1
		});
		expect((await getProjectStore().find(w.project._id))?.bucketId).toBe(
			w.from._id
		);
	});

	it('applies a change confirmed with the counts shown, recorded once in the trail of both buckets', async () => {
		const w = await world();

		const res = await send(
			'PUT',
			`/admin/api/projects/${w.project._id}/bucket`,
			w.cookie,
			{
				bucketId: w.to._id,
				confirm: true,
				expect: { applications: 2, resources: 1 }
			}
		);

		expect(res.status).toBe(200);
		expect((await getProjectStore().find(w.project._id))?.bucketId).toBe(
			w.to._id
		);
		const { entries } = await adminAuditStore.list({
			targetId: w.project._id
		});
		expect(
			entries.map((e) => [e.action, e.bucketId, e.formerBucketId])
		).toEqual([['project.bucket.assign', w.to._id, w.from._id]]);
		for (const bucket of [w.from._id, w.to._id]) {
			const trail = await adminAuditStore.list({ bucket });
			expect(trail.entries.map((e) => e.targetId)).toContain(w.project._id);
		}
	});

	it('names an identifier already declared in the destination as blocking the change', async () => {
		const w = await world();
		const resident = await getProjectStore().create({
			name: 'Resident',
			slug: slug('resident'),
			ownerGroupId: w.team._id,
			bucketId: w.to._id
		});
		await declare(w.to._id, resident._id, w.identifier);

		const res = await send(
			'PUT',
			`/admin/api/projects/${w.project._id}/bucket`,
			w.cookie,
			{ bucketId: w.to._id }
		);

		const preview = shaped(Preview, res.body);
		expect(preview.conflicts).toEqual([w.identifier]);
		expect(preview.blocked).toBe(true);
	});

	it('refuses a blocked change confirmed anyway, and moves nothing', async () => {
		const w = await world();
		const resident = await getProjectStore().create({
			name: 'Resident',
			slug: slug('resident'),
			ownerGroupId: w.team._id,
			bucketId: w.to._id
		});
		await declare(w.to._id, resident._id, w.identifier);

		const res = await send(
			'PUT',
			`/admin/api/projects/${w.project._id}/bucket`,
			w.cookie,
			{
				bucketId: w.to._id,
				confirm: true,
				expect: { applications: 2, resources: 1 }
			}
		);

		expect(res.status).toBe(409);
		expect(
			shaped(Type.Object({ conflicts: Type.Array(Type.String()) }), res.body)
				.conflicts
		).toEqual([w.identifier]);
		expect((await getProjectStore().find(w.project._id))?.bucketId).toBe(
			w.from._id
		);
		expect(await trailOf(w.project._id)).toBe(0);
	});

	it('refuses a group administrator the Default bucket before describing anything', async () => {
		const w = await world();

		const res = await send(
			'PUT',
			`/admin/api/projects/${w.project._id}/bucket`,
			w.cookie,
			{ bucketId: DEFAULT_BUCKET_ID }
		);

		expect(res.status).toBe(403);
		expect(Object.keys(shaped(Refusal, res.body))).not.toContain(
			'applications'
		);
		expect((await getProjectStore().find(w.project._id))?.bucketId).toBe(
			w.from._id
		);
	});

	it("moves a tenant group's project onto the Default bucket when a super administrator confirms the counts shown, recorded in the trail of the bucket it left", async () => {
		const w = await world();
		const cookie = await cookieFor(await createAdministrator('super'));
		const path = `/admin/api/projects/${w.project._id}/bucket`;

		const preview = await send('PUT', path, cookie, {
			bucketId: DEFAULT_BUCKET_ID
		});
		const res = await send('PUT', path, cookie, {
			bucketId: DEFAULT_BUCKET_ID,
			confirm: true,
			expect: { applications: 2, resources: 1 }
		});

		expect(shaped(Preview, preview.body).to).toMatchObject({
			bucketId: DEFAULT_BUCKET_ID,
			issuer: ISSUER
		});
		expect(res.status).toBe(200);
		expect((await getProjectStore().find(w.project._id))?.bucketId).toBe(
			DEFAULT_BUCKET_ID
		);
		expect(
			(await getProtectedResourceStore().find(ROOT_NAMESPACE, w.identifier))
				?.projectId
		).toBe(w.project._id);
		const { entries } = await adminAuditStore.list({ bucket: w.from._id });
		expect(
			entries
				.filter((e) => e.targetId === w.project._id)
				.map((e) => [e.action, e.formerBucketId])
		).toEqual([['project.bucket.assign', w.from._id]]);
	});

	it('records nothing in the trail for a preview of a change', async () => {
		const w = await world();

		await send('PUT', `/admin/api/projects/${w.project._id}/bucket`, w.cookie, {
			bucketId: w.to._id
		});

		expect(await trailOf(w.project._id)).toBe(0);
	});

	it('refuses a caller outside the project before describing anything', async () => {
		const w = await world();
		const outsider: User = await createAdministrator('plain');

		const res = await send(
			'PUT',
			`/admin/api/projects/${w.project._id}/bucket`,
			await cookieFor(outsider),
			{ bucketId: w.to._id }
		);

		expect(res.status).toBe(403);
		expect(Object.keys(shaped(Refusal, res.body))).not.toContain(
			'applications'
		);
	});

	it('refuses a destination bucket the caller cannot reach before describing anything', async () => {
		const w = await world();
		const elsewhere = await getBucketStore().create({
			name: 'Somebody else',
			slug: slug('else'),
			ownerGroupId: `group-${nanoid()}`
		});

		const res = await send(
			'PUT',
			`/admin/api/projects/${w.project._id}/bucket`,
			w.cookie,
			{ bucketId: elsewhere._id }
		);

		expect(res.status).toBe(403);
		expect(Object.keys(shaped(Refusal, res.body))).not.toContain(
			'applications'
		);
	});
});
