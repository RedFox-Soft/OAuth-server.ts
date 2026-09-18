import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import {
	bucketAtHost,
	forgetBucketAddresses
} from 'lib/admin/auth/bucketAddress.ts';
import { forgetHostArrivals } from 'lib/admin/auth/hostArrivals.ts';
import { sessionFor } from '../admin_session.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes);

async function superCookie() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`super-${Math.random()}@x.io`,
		'hash',
		['super_admin']
	);
	return `${ADMIN_SESSION_COOKIE}=${(await sessionFor(user))._id}`;
}

async function readBucket(cookie: string, id: string) {
	const response = await app.handle(
		new Request(`http://e.ly/admin/api/buckets/${id}`, {
			redirect: 'manual',
			headers: { cookie }
		})
	);
	return (await response.json()) as {
		address?: Record<string, unknown>;
	};
}

/* The recorder never delays a response and is therefore not awaited by its caller. A read taken in the
 * same tick would race it, so this yields once — which is what a real operator's next page load does. */
async function settle() {
	await new Promise((resolve) => setTimeout(resolve, 20));
}

/**
 * @proves An operator can tell whether a bucket's address has ever been reached, and is never told that
 * a name resolves or that a certificate is valid — facts this server cannot establish.
 */
describe('reporting whether an address works (US4)', () => {
	let cookie: string;
	let counter = 0;

	beforeEach(async () => {
		await ensureAdminSeed();
		forgetBucketAddresses();
		forgetHostArrivals();
		cookie = await superCookie();
		counter += 1;
	});

	it('reports that no request has arrived at a bucket host, when none has', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Unreached',
			host: `unreached-${counter}.e.ly`
		});

		const { address } = await readBucket(cookie, bucket._id);

		expect(address?.requestsArrived).toBe(false);
		expect(address?.lastArrivalAt).toBeNull();
	});

	it('reports when a request last arrived, once one has', async () => {
		const host = `reached-${counter}.e.ly`;
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Reached',
			host
		});

		await bucketAtHost(host);
		await settle();

		const { address } = await readBucket(cookie, bucket._id);

		expect(address?.requestsArrived).toBe(true);
		expect(address?.lastArrivalAt).not.toBeNull();
	});

	it('names the record an operator has to create, rather than describing it', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Guided',
			host: `guided-${counter}.e.ly`
		});

		const { address } = await readBucket(cookie, bucket._id);

		/* A record that can be copied, not an errand. */
		expect(address?.dnsRecord).toEqual({
			name: `guided-${counter}.e.ly`,
			type: 'CNAME',
			value: 'e.ly'
		});
	});

	it('never reports that a name resolves or that a certificate is valid', async () => {
		const host = `honest-${counter}.e.ly`;
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Honest',
			host
		});

		await bucketAtHost(host);
		await settle();

		const { address } = await readBucket(cookie, bucket._id);

		/* Neither is a fact this server can establish, and a confident wrong answer is worse than none:
		 * a name verified today is repointed tomorrow, and a certificate expires. */
		expect(JSON.stringify(address)).not.toMatch(/verified|valid certificate/i);
		expect(address?.stillToDo).toContain('certificate');
	});

	it('carries no address section for a bucket addressed by a path', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Pathy',
			slug: `pathy-${counter}`
		});

		const { address } = await readBucket(cookie, bucket._id);

		/* There is no hostname to point anywhere, so there is nothing to report and nothing to do. */
		expect(address).toBeUndefined();
	});
});
