import { describe, it, expect, beforeEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getProjectStore,
	getUserStore
} from 'lib/adapters/index.ts';
import {
	ADMIN_BUCKET_ID,
	ADMIN_SESSION_COOKIE,
	DEFAULT_BUCKET_ID,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { issuerFor } from 'lib/configs/issuer.ts';
import { sessionFor } from '../admin_session.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes);

async function cookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

async function changeAddress(
	cookie: string,
	id: string,
	body: Record<string, unknown>
) {
	const response = await app.handle(
		new Request(`http://e.ly/admin/api/buckets/${id}/address`, {
			method: 'POST',
			redirect: 'manual',
			headers: { 'content-type': 'application/json', cookie },
			body: JSON.stringify(body)
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		body: text ? (JSON.parse(text) as Record<string, unknown>) : {}
	};
}

async function seedBucketWithClients(slug: string, clientIds: string[]) {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `Movable ${slug}`,
		slug
	});
	const project = await getProjectStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `Movable ${slug}`,
		slug: `proj-${slug}`
	});
	await getProjectStore().update(project._id, {
		bucketId: bucket._id,
		clientIds
	});
	return bucket._id;
}

/**
 * @proves Moving a bucket is an operation of its own: it shows what it will break before it breaks it,
 * completes only on a separate confirmation, leaves the previous address answering nothing, and is
 * refused outright for a bucket served at the root.
 */
describe('moving a bucket to a different address (US3)', () => {
	let superCookie: string;
	let counter = 0;

	beforeEach(async () => {
		await ensureAdminSeed();
		forgetBucketAddresses();
		superCookie = await cookieFor(['super_admin']);
		counter += 1;
	});

	it('names every client that will need reconfiguring, before an address changes', async () => {
		const id = await seedBucketWithClients(`preview-${counter}`, [
			'billing-api',
			'admin-console-app'
		]);

		const { body } = await changeAddress(superCookie, id, {
			host: `preview-${counter}.e.ly`
		});

		/* Named rather than counted: "2 clients" tells an operator nothing they can act on, and a list of
		 * ids is what they take to whoever owns each one. */
		expect(body.clientsNeedingReconfiguration).toEqual([
			'admin-console-app',
			'billing-api'
		]);
	});

	it('refuses to complete an address change without a separate confirmation', async () => {
		const id = await seedBucketWithClients(`unconfirmed-${counter}`, []);

		const { status, body } = await changeAddress(superCookie, id, {
			host: `unconfirmed-${counter}.e.ly`
		});

		expect(status).toBe(409);
		expect(body.confirmationRequired).toBe(true);

		/* Nothing changed: the bucket still answers where it did. */
		const after = await getBucketStore().find(id);
		expect(after?.slug).toBe(`unconfirmed-${counter}`);
		expect(after?.host).toBeUndefined();
	});

	/* The other half of the window the create route has: a move is a write after a lookup too, so the
	 * operator who loses the race is owed the same refusal rather than an internal fault. The stubbed
	 * lookup is the race — it answers "free" about a name another bucket holds. */
	it('refuses with a conflict when the hostname is taken between the check and the write', async () => {
		const id = await seedBucketWithClients(`raced-${counter}`, []);
		const held = `holder-${counter}.e.ly`;
		await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: `Holder ${counter}`,
			host: held
		});
		const lookup = spyOn(getBucketStore(), 'findByHost').mockResolvedValue(
			null
		);

		try {
			const { status } = await changeAddress(superCookie, id, {
				host: held,
				confirm: true
			});

			expect(status).toBe(409);
		} finally {
			lookup.mockRestore();
		}
	});

	it('changes the issuer identifier when the change is confirmed', async () => {
		const id = await seedBucketWithClients(`moved-${counter}`, []);
		const host = `moved-${counter}.e.ly`;

		const { status } = await changeAddress(superCookie, id, {
			host,
			confirm: true
		});
		expect(status).toBe(200);

		const after = await getBucketStore().find(id);
		expect(after?.host).toBe(host);
		expect(issuerFor(after!)).toBe(`http://${host}`);
	});

	it('stops answering at the previous address once the change is confirmed', async () => {
		const slug = `vacated-${counter}`;
		const id = await seedBucketWithClients(slug, []);

		await changeAddress(superCookie, id, {
			host: `vacated-${counter}.e.ly`,
			confirm: true
		});
		forgetBucketAddresses();

		/* An old address that quietly keeps working is a second issuer identifier for one population,
		 * which is the one thing an issuer identifier may not have. */
		expect(await getBucketStore().findBySlug(slug)).toBeNull();
	});

	it('reports one address for a bucket, never two', async () => {
		const id = await seedBucketWithClients(`single-${counter}`, []);

		await changeAddress(superCookie, id, {
			host: `single-${counter}.e.ly`,
			confirm: true
		});

		const after = await getBucketStore().find(id);

		/* The slug is removed rather than left beside the hostname. Both present would make the bucket
		 * reachable two ways, and the failure surfaces far away — as a token whose issuer disagrees with
		 * the metadata that advertised the endpoint it came from. */
		expect(after?.slug).toBeUndefined();
		expect(after?.host).toBe(`single-${counter}.e.ly`);
	});

	it('refuses to move a bucket that is served at the root', async () => {
		const { status } = await changeAddress(superCookie, DEFAULT_BUCKET_ID, {
			host: `root-${counter}.e.ly`,
			confirm: true
		});

		/* Its issuer is the instance's own. Moving the administrators bucket would also take the console
		 * with it, locking every operator out of the surface that could move it back. */
		expect(status).toBe(403);
	});

	it('refuses an address change from an administrator who administers only a group', async () => {
		const id = await seedBucketWithClients(`escalate-${counter}`, []);
		const projectAdmin = await cookieFor(['project_admin']);

		const { status } = await changeAddress(projectAdmin, id, {
			host: `escalate-${counter}.e.ly`,
			confirm: true
		});

		expect(status).toBe(403);
	});
});
