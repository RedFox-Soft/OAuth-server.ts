import { describe, it, expect, beforeAll } from 'bun:test';
import { Type } from '@sinclair/typebox';

import { adminApiRoutes } from 'lib/admin/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import { shaped } from '../shape.ts';

const Page = Type.Object({
	users: Type.Array(Type.Object({ _id: Type.String(), email: Type.String() })),
	totalResults: Type.Number()
});

let cookie: string;

async function list(bucketId: string, query = '') {
	const res = await adminApiRoutes.handle(
		new Request(`http://e.ly/admin/api/projects/${bucketId}/users${query}`, {
			headers: { cookie }
		})
	);
	return { status: res.status, body: (await res.json()) as unknown };
}

async function emailsListed(bucketId: string, query: string) {
	const { body } = await list(bucketId, query);
	return shaped(Page, body).users.map((u) => u.email);
}

/*
 * A bucket of five people, each in one state the filters tell apart: ann is active and local, bea is
 * deactivated, cid is locked, dee is a directory's and verified with an authenticator, eve is unverified.
 */
async function populatedBucket() {
	const bucket = await getBucketStore().create({
		name: `list-${Math.random()}`,
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	const store = getUserStore(bucket._id);
	const ann = await store.create('ann@example.com', 'h', true);
	const bea = await store.create('bea@example.com', 'h', true);
	await store.update(bea._id, { active: false });
	const cid = await store.create('cid@example.com', 'h', true);
	await store.update(cid._id, {
		lockedLocally: { at: new Date(), by: 'someone', reason: 'probe' }
	});
	const dee = await store.create('dee@example.com', 'h', true);
	await store.update(dee._id, {
		provisionedBy: 'conn-dee',
		userName: 'Dee.Directory',
		totp: { secret: 'JBSWY3DPEHPK3PXP', enrolledAt: new Date(), lastStep: 0 }
	});
	await store.create('eve@example.com', 'h', false);
	return { bucketId: bucket._id, ann };
}

/**
 * @proves An administrator reads a bucket's people a page at a time, in email order with the total, found by
 * the start of an email or username in any case or by exact id and narrowed by state — and a malformed or
 * mistyped query is refused rather than answered with everyone.
 */
describe('listing a bucket’s users', () => {
	beforeAll(async () => {
		await ensureAdminSeed();
		const admin = await createAdministrator('super');
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(admin))._id}`;
	});

	it('answers a page in email order with the total of every match', async () => {
		const { bucketId } = await populatedBucket();

		const { status, body } = await list(bucketId, '?count=2');

		expect(status).toBe(200);
		const page = shaped(Page, body);
		expect(page.users.map((u) => u.email)).toEqual([
			'ann@example.com',
			'bea@example.com'
		]);
		expect(page.totalResults).toBe(5);
	});

	it('answers only the page asked for', async () => {
		const { bucketId } = await populatedBucket();

		expect(await emailsListed(bucketId, '?startIndex=3&count=2')).toEqual([
			'cid@example.com',
			'dee@example.com'
		]);
	});

	it('finds a person by the start of their email in another letter case', async () => {
		const { bucketId } = await populatedBucket();

		expect(await emailsListed(bucketId, '?q=ANN')).toEqual(['ann@example.com']);
	});

	it('finds a person by the start of their username', async () => {
		const { bucketId } = await populatedBucket();

		expect(await emailsListed(bucketId, '?q=dee.dir')).toEqual([
			'dee@example.com'
		]);
	});

	it('finds a person by their exact id', async () => {
		const { bucketId, ann } = await populatedBucket();

		expect(
			await emailsListed(bucketId, `?q=${encodeURIComponent(ann._id)}`)
		).toEqual(['ann@example.com']);
	});

	it('narrows to the people who are active and unlocked', async () => {
		const { bucketId } = await populatedBucket();

		expect(await emailsListed(bucketId, '?status=active')).toEqual([
			'ann@example.com',
			'dee@example.com',
			'eve@example.com'
		]);
	});

	it('narrows to deactivated people', async () => {
		const { bucketId } = await populatedBucket();

		expect(await emailsListed(bucketId, '?status=deactivated')).toEqual([
			'bea@example.com'
		]);
	});

	it('narrows to locked people', async () => {
		const { bucketId } = await populatedBucket();

		expect(await emailsListed(bucketId, '?status=locked')).toEqual([
			'cid@example.com'
		]);
	});

	it('narrows to the people administrators manage here', async () => {
		const { bucketId } = await populatedBucket();

		expect(await emailsListed(bucketId, '?managedBy=console')).not.toContain(
			'dee@example.com'
		);
	});

	it('narrows to one connection’s people', async () => {
		const { bucketId } = await populatedBucket();

		expect(await emailsListed(bucketId, '?managedBy=conn-dee')).toEqual([
			'dee@example.com'
		]);
	});

	it('narrows to unverified people', async () => {
		const { bucketId } = await populatedBucket();

		expect(await emailsListed(bucketId, '?verified=no')).toEqual([
			'eve@example.com'
		]);
	});

	it('narrows to people holding an authenticator', async () => {
		const { bucketId } = await populatedBucket();

		expect(await emailsListed(bucketId, '?authenticator=yes')).toEqual([
			'dee@example.com'
		]);
	});

	it('refuses a page larger than the list allows', async () => {
		const { bucketId } = await populatedBucket();

		expect((await list(bucketId, '?count=500')).status).toBe(422);
	});

	it('refuses a status it does not know', async () => {
		const { bucketId } = await populatedBucket();

		expect((await list(bucketId, '?status=everyone')).status).toBe(422);
	});

	it('refuses a mistyped filter rather than answering with everyone', async () => {
		const { bucketId } = await populatedBucket();

		const { status, body } = await list(bucketId, '?staus=locked');

		expect(status).toBe(422);
		expect(body).toHaveProperty('field', 'staus');
	});
});
