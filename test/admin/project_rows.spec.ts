import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getProjectStore } from 'lib/adapters/index.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator } from '../administrators.ts';
import {
	bucketWithProjects,
	cookieFor,
	regularGroup
} from './ownership_fixtures.ts';

const app = new Elysia({ normalize: false })
	.use(resolveAdmin)
	.use(projectRoutes);

async function read(path: string, cookie: string): Promise<unknown> {
	const response = await app.handle(
		new Request(`http://e.ly${path}`, { headers: { cookie } })
	);
	expect(response.status).toBe(200);
	return response.json();
}

const Row = Type.Object({
	_id: Type.String(),
	bucket: Type.Union([
		Type.Object({
			id: Type.String(),
			name: Type.String(),
			addressForm: Type.String()
		}),
		Type.Null()
	]),
	clientCount: Type.Number()
});

/**
 * @proves A project's row and read name the bucket its applications sign in through and how many
 * applications it holds, for a super administrator whose scope is another group as for its own members.
 */
describe('project rows', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it("names each project's bucket to a super administrator working in another scope", async () => {
		const owner = await createAdministrator('plain');
		const team = await regularGroup([owner]);
		const {
			bucket,
			projects: [bucketed]
		} = await bucketWithProjects(team._id, 1);
		const unbucketed = await getProjectStore().create({
			name: 'No bucket',
			slug: `nb-${nanoid()
				.toLowerCase()
				.replace(/[^a-z0-9]/g, '')}`,
			ownerGroupId: team._id,
			clientIds: ['one', 'two']
		});
		const superAdmin = await createAdministrator('super');

		const rows = shaped(
			Type.Array(Row),
			await read('/admin/api/projects', await cookieFor(superAdmin))
		);

		const byId = new Map(rows.map((row) => [row._id, row]));
		expect(byId.get(bucketed._id)?.bucket).toEqual({
			id: bucket._id,
			name: bucket.name,
			addressForm: 'path'
		});
		expect(byId.get(unbucketed._id)?.bucket).toBeNull();
		expect(byId.get(unbucketed._id)?.clientCount).toBe(2);
	});

	it('names the bucket on the read of one project', async () => {
		const owner = await createAdministrator('plain');
		const team = await regularGroup([owner]);
		const {
			bucket,
			projects: [bucketed]
		} = await bucketWithProjects(team._id, 1);

		const row = shaped(
			Row,
			await read(`/admin/api/projects/${bucketed._id}`, await cookieFor(owner))
		);

		expect(row.bucket?.name).toBe(bucket.name);
		expect(row.clientCount).toBe(0);
	});
});
