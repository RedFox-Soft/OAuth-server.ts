import { describe, it, expect, beforeAll, afterEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';

import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { activityRoutes } from 'lib/admin/activity/routes.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getActivityStore, getGroupStore } from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import type { Group, User } from 'lib/adapters/types.ts';
import type { OverviewAnswer } from 'lib/activity/overview.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { createAdministrator } from '../administrators.ts';
import {
	bucketWithClients,
	cookieFor,
	regularGroup
} from './ownership_fixtures.ts';
import { atDay, startCounting } from '../activity/fixtures.ts';

const app = new Elysia()
	.use(resolveAdmin)
	.use(activityRoutes)
	.use(bucketRoutes);

/* A day of March 2031; February is closed. */
const NOW = '2031-03-15T12:00:00Z';
let restoreClock: (() => void) | undefined;

async function read(path: string, as: User) {
	const response = await app.handle(
		new Request(`http://e.ly${path}`, {
			headers: { cookie: await cookieFor(as) }
		})
	);
	return { status: response.status, text: await response.text() };
}

/* Plain JSON rather than Eden, which would revive the period strings into dates nobody else sees. */
async function overview(as: User): Promise<OverviewAnswer> {
	const reply = await read('/admin/api/activity', as);
	expect(reply.status).toBe(200);
	return JSON.parse(reply.text) as OverviewAnswer;
}

async function markMany(bucketId: string, count: number, iso: string) {
	const prefix = nanoid();
	for (let i = 0; i < count; i += 1) {
		await getActivityStore().mark({
			bucketId,
			accountId: `${prefix}-${String(i)}`,
			kind: 'local',
			provisioned: false,
			at: new Date(iso)
		});
	}
}

async function bucketOf(group: Group): Promise<string> {
	return (await bucketWithClients(group._id, 0)).bucket._id;
}

/* Deleted and then destroyed at once: a deletion only schedules the destruction (specs/090). */
async function destroy(bucketId: string, as: User) {
	for (const [method, path] of [
		['DELETE', `/admin/api/buckets/${bucketId}`],
		['POST', `/admin/api/buckets/${bucketId}/purge`]
	] as const) {
		const response = await app.handle(
			new Request(`http://e.ly${path}`, {
				method,
				headers: { cookie: await cookieFor(as) }
			})
		);
		expect(response.status).toBeLessThan(300);
	}
}

const ids = (answer: OverviewAnswer) =>
	answer.buckets.map((row) => row.bucketId).sort();

afterEach(() => {
	restoreClock?.();
	restoreClock = undefined;
});

/**
 * @proves An administrator who is not a super administrator reads the usage overview over exactly the buckets
 * their groups own — as an owner or a plain member — with those groups as the customers and every total
 * computed over those buckets alone, and learns nothing about any other group's bucket, the instance's own
 * buckets or the instance's totals (spec 091, User Story 3).
 */
describe('the usage overview, for an administrator of some groups', () => {
	let alice: User;
	let bob: User;
	let carol: User;
	let loner: User;
	let one: Group;
	let shared: Group;
	let other: Group;
	let inOne: string;
	let inShared: string;
	let inOther: string;

	beforeAll(async () => {
		await ensureAdminSeed();
		await startCounting();
		alice = await createAdministrator('plain');
		bob = await createAdministrator('plain');
		carol = await createAdministrator('plain');
		loner = await createAdministrator('plain');
		/* Alice owns one and is a plain member of the shared group; Bob owns the shared group and is a plain member of the third, which Carol owns. */
		one = await regularGroup([alice]);
		shared = await regularGroup([bob], [alice]);
		other = await regularGroup([carol], [bob]);
		inOne = await bucketOf(one);
		inShared = await bucketOf(shared);
		inOther = await bucketOf(other);
		await markMany(inOne, 3, '2031-03-02T10:00:00Z');
		await markMany(inShared, 2, '2031-03-03T10:00:00Z');
		await markMany(inOther, 5, '2031-03-04T10:00:00Z');
	});

	it('lists exactly the buckets of the groups the administrator belongs to, under those groups', async () => {
		restoreClock = atDay(NOW);

		const forAlice = await overview(alice);
		const forBob = await overview(bob);

		expect(ids(forAlice)).toEqual([inOne, inShared].sort());
		expect(ids(forBob)).toEqual([inShared, inOther].sort());
		expect(forAlice.customers.map((c) => c.customer.groupId).sort()).toEqual(
			[one._id, shared._id].sort()
		);
	});

	it('computes every total over those buckets alone', async () => {
		restoreClock = atDay(NOW);

		const forAlice = await overview(alice);
		const forBob = await overview(bob);

		expect(forAlice.instance.months[0]?.total).toBe(5);
		expect(forBob.instance.months[0]?.total).toBe(7);
		expect(forAlice.instance.activeBuckets).toBe(2);
	});

	it("discloses nothing of another group's bucket: not its id, its name, its group or its owner", async () => {
		restoreClock = atDay(NOW);

		const text = JSON.stringify(await overview(alice));

		expect(text).not.toContain(inOther);
		expect(text).not.toContain(other._id);
		expect(text).not.toContain(other.name);
		expect(text).not.toContain(carol.email);
	});

	it("never lists the instance's own buckets to anyone but a super administrator", async () => {
		restoreClock = atDay(NOW);

		const listed = ids(await overview(alice));

		expect(listed).not.toContain(DEFAULT_BUCKET_ID);
		expect(listed).not.toContain(ADMIN_BUCKET_ID);
	});

	it('shows a plain member of a group what its owner sees of that group', async () => {
		restoreClock = atDay(NOW);

		const asMember = (await overview(alice)).buckets.find(
			(row) => row.bucketId === inShared
		);
		const asOwner = (await overview(bob)).buckets.find(
			(row) => row.bucketId === inShared
		);

		expect(asMember).toBeDefined();
		expect(asMember).toEqual(asOwner);
	});

	it('answers an administrator whose groups own nothing with an empty overview, not a refusal', async () => {
		restoreClock = atDay(NOW);

		const answer = await overview(loner);

		expect(answer.buckets).toEqual([]);
		expect(answer.customers).toEqual([]);
	});
});

/**
 * @proves A bucket a group deleted stays readable to that group — its row in the overview and its usage
 * history — because its active users counted in that group's months; to anyone else it is refused exactly as
 * an id that never existed, and a deletion record that names no group stays a super administrator's alone
 * (spec 091, User Story 4).
 */
describe('a deleted bucket, for the group that owned it last', () => {
	let owner: User;
	let member: User;
	let stranger: User;
	let leaver: User;
	let team: Group;
	let deletedId: string;

	beforeAll(async () => {
		await ensureAdminSeed();
		await startCounting();
		owner = await createAdministrator('plain');
		member = await createAdministrator('plain');
		stranger = await createAdministrator('plain');
		leaver = await createAdministrator('plain');
		team = await regularGroup([owner], [member, leaver]);
		await regularGroup([stranger]);
		deletedId = await bucketOf(team);
		await markMany(deletedId, 4, '2031-02-10T10:00:00Z');
		await destroy(deletedId, owner);
	});

	it('lists it to a member of that group, marked deleted and counted in February', async () => {
		restoreClock = atDay(NOW);

		const row = (await overview(member)).buckets.find(
			(b) => b.bucketId === deletedId
		);

		expect(row?.deleted).not.toBeNull();
		expect(row?.previous?.total).toBe(4);
		expect(row?.customer.groupId).toBe(team._id);
	});

	it('opens its history to a member of that group', async () => {
		restoreClock = atDay(NOW);

		const reply = await read(
			`/admin/api/buckets/${deletedId}/activity`,
			member
		);

		expect(reply.status).toBe(200);
		const body = JSON.parse(reply.text) as {
			deletedAt: string | null;
			lastOwner: { groupId: string } | null;
		};
		expect(body.deletedAt).not.toBeNull();
		expect(body.lastOwner?.groupId).toBe(team._id);
	});

	it('refuses it to anyone else exactly as an id that never existed', async () => {
		restoreClock = atDay(NOW);

		const deleted = await read(
			`/admin/api/buckets/${deletedId}/activity`,
			stranger
		);
		const unknown = await read(
			`/admin/api/buckets/${nanoid().toLowerCase()}/activity`,
			stranger
		);

		expect(deleted).toEqual(unknown);
		expect(deleted.status).toBe(403);
		expect(ids(await overview(stranger))).not.toContain(deletedId);
	});

	it('refuses it to somebody who has left the group since', async () => {
		await getGroupStore().update(team._id, {
			members: [
				{ userId: owner._id, role: 'owner' },
				{ userId: member._id, role: 'member' }
			]
		});
		restoreClock = atDay(NOW);

		const reply = await read(
			`/admin/api/buckets/${deletedId}/activity`,
			leaver
		);

		expect(reply.status).toBe(403);
		expect(ids(await overview(leaver))).not.toContain(deletedId);
	});

	it('keeps a deletion record that names no group a super administrator’s alone', async () => {
		const id = `pre-077-${nanoid().toLowerCase()}`;
		const store = getActivityStore();
		/* The tombstone exactly as spec 076 wrote it, before an owner was kept. */
		const old = {
			_id: `bucket|${id}`,
			type: 'tombstone' as const,
			bucketId: id,
			bucketName: 'old bucket',
			createdAt: new Date(0),
			deletedAt: new Date('2031-02-20T00:00:00Z')
		};
		const stored = store.tombstones.bind(store);
		const listed = spyOn(store, 'tombstones').mockImplementation(async () => [
			...(await stored()),
			old
		]);
		const found = spyOn(store, 'tombstone').mockImplementation(async () => old);
		restoreClock = atDay(NOW);

		const superAdmin = await createAdministrator('super');
		const asMember = await read(`/admin/api/buckets/${id}/activity`, member);
		const asSuper = await read(`/admin/api/buckets/${id}/activity`, superAdmin);
		const memberSees = ids(await overview(member));
		listed.mockRestore();
		found.mockRestore();

		expect(memberSees).not.toContain(id);
		expect(asMember.status).toBe(403);
		expect(asSuper.status).toBe(200);
	});
});
