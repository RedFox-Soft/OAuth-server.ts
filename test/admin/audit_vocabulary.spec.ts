import { describe, it, expect, beforeAll } from 'bun:test';
import { Elysia } from 'elysia';
import { Type } from '@sinclair/typebox';

import { adminApiRoutes } from 'lib/admin/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { adminAuditStore } from 'lib/adapters/index.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { shaped } from 'test/shape.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';

const app = new Elysia({ normalize: false }).use(adminApiRoutes);

const Entry = Type.Object({
	action: Type.String(),
	targetType: Type.String(),
	targetId: Type.String(),
	ownerTeamId: Type.Optional(Type.Union([Type.String(), Type.Null()]))
});
const Page = Type.Object({ entries: Type.Array(Entry), total: Type.Number() });

async function trail(cookie: string, query: Record<string, string>) {
	const response = await app.handle(
		new Request(
			`http://e.ly/admin/api/audit?${new URLSearchParams(query).toString()}`,
			{ headers: { cookie } }
		)
	);
	return { status: response.status, body: (await response.json()) as unknown };
}

async function entries(cookie: string, query: Record<string, string>) {
	const { status, body } = await trail(cookie, query);
	expect(status).toBe(200);
	return shaped(Page, body).entries;
}

interface World {
	cookie: string;
	teamId: string;
	projectId: string;
	retiredId: string;
	endUserGroupId: string;
}

let w: World;

/**
 * @proves An administrator reads the trail in today's words, whenever an entry was written: a project's
 * creation recorded before the rename reads and filters as a project's, a team's changes and an end-user
 * group's changes are each found by their own name, and an entry about the projects removed before
 * buckets became projects is shown as a retired project — never as one of today's.
 */
describe('the audit trail, read after the rename', () => {
	beforeAll(async () => {
		await ensureAdminSeed();
		const owner = await createAdministrator('plain');
		const team = await regularGroup([owner]);
		const cookie = await cookieFor(owner);
		const projectId = `p-${nanoid()}`;
		const retiredId = `r-${nanoid()}`;
		const endUserGroupId = `g-${nanoid()}`;
		const actor = { actorId: owner._id, actorEmail: owner.email };
		// Stored exactly as the trail stored them before the rename: storage keeps its names.
		await adminAuditStore.record({
			...actor,
			action: 'bucket.create',
			targetType: 'UserBucket',
			targetId: projectId,
			ownerGroupId: team._id
		});
		await adminAuditStore.record({
			...actor,
			action: 'project.create',
			targetType: 'Project',
			targetId: retiredId,
			ownerGroupId: team._id
		});
		await adminAuditStore.record({
			...actor,
			action: 'group.member.add',
			targetType: 'Group',
			targetId: team._id,
			ownerGroupId: team._id
		});
		await adminAuditStore.record({
			...actor,
			action: 'bucketgroup.create',
			targetType: 'BucketGroup',
			targetId: endUserGroupId,
			targetScope: projectId,
			ownerGroupId: team._id
		});
		w = { cookie, teamId: team._id, projectId, retiredId, endUserGroupId };
	});

	it('lists a project creation recorded before the rename as project.create, naming its project and team', async () => {
		const [entry] = await entries(w.cookie, { targetId: w.projectId });
		expect(entry).toMatchObject({
			action: 'project.create',
			targetType: 'Project',
			targetId: w.projectId,
			ownerTeamId: w.teamId
		});
	});

	it('finds a creation recorded before the rename by the action project.create', async () => {
		const found = await entries(w.cookie, { action: 'project.create' });
		expect(found.map((e) => e.targetId)).toEqual([w.projectId]);
	});

	it('shows an entry about a project removed before the rename as a retired project, outside the project prefix', async () => {
		const [retired] = await entries(w.cookie, { targetId: w.retiredId });
		expect(retired).toMatchObject({
			action: 'retiredproject.create',
			targetType: 'RetiredProject'
		});
		const projects = await entries(w.cookie, { actionPrefix: 'project.' });
		expect(projects.map((e) => e.targetId)).not.toContain(w.retiredId);
	});

	it('finds team changes by the team prefix and end-user group changes by the group prefix, each without the other', async () => {
		const teams = await entries(w.cookie, { actionPrefix: 'team.' });
		const groups = await entries(w.cookie, { actionPrefix: 'group.' });
		expect(teams.map((e) => [e.action, e.targetId])).toEqual([
			['team.member.add', w.teamId]
		]);
		expect(groups.map((e) => [e.action, e.targetId])).toEqual([
			['group.create', w.endUserGroupId]
		]);
	});

	it('refuses a prefix that stops inside a renamed word', async () => {
		const { status } = await trail(w.cookie, { actionPrefix: 'proj' });
		expect(status).toBe(422);
	});
});
