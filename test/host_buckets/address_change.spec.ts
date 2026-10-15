import { describe, it, expect, beforeEach, spyOn } from 'bun:test';
import { Elysia } from 'elysia';
import { adminApiRoutes } from 'lib/admin/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getProtectedResourceStore,
	getProvisioningConnectionStore
} from 'lib/adapters/index.ts';
import type { User } from 'lib/adapters/types.ts';
import {
	ADMIN_SESSION_COOKIE,
	DEFAULT_BUCKET_ID,
	UNASSIGNED_GROUP_ID
} from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { createClient } from 'lib/admin/clients/service.ts';
import { issuerFor } from 'lib/configs/issuer.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { personalGroupId, sessionFor } from '../admin_session.ts';
import { Type } from '@sinclair/typebox';
import { present, shaped } from 'test/shape.ts';
import { createAdministrator, type AdminKind } from '../administrators.ts';
import { regularGroup } from '../admin/ownership_fixtures.ts';
import { provider } from '../scim/helpers.ts';

const app = new Elysia().use(adminApiRoutes);

async function sessionCookie(user: User) {
	const session = await sessionFor(user);
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

async function cookieFor(kind: AdminKind) {
	return sessionCookie(
		await createAdministrator(kind, `${kind}-${Math.random()}@x.io`)
	);
}

/* What a preview that reaches nothing counts: the expectation a commit on an unused bucket carries. */
const NOTHING = { applications: 0, connections: 0, providers: 0, resources: 0 };

const Preview = Type.Object({
	from: Type.String(),
	to: Type.String(),
	applications: Type.Array(
		Type.Object({
			clientId: Type.String(),
			name: Type.Union([Type.String(), Type.Null()])
		})
	),
	connections: Type.Array(
		Type.Object({ id: Type.String(), displayName: Type.String() })
	),
	providers: Type.Array(
		Type.Object({
			id: Type.String(),
			displayName: Type.String(),
			newCallback: Type.String()
		})
	),
	resources: Type.Array(
		Type.Object({
			identifier: Type.String(),
			name: Type.String()
		})
	),
	namespaceMove: Type.Boolean(),
	expect: Type.Object({
		applications: Type.Number(),
		connections: Type.Number(),
		providers: Type.Number(),
		resources: Type.Number()
	})
});

const AuditPage = Type.Object({
	entries: Type.Array(
		Type.Object({
			action: Type.String(),
			from: Type.Optional(Type.Union([Type.String(), Type.Null()])),
			to: Type.Optional(Type.Union([Type.String(), Type.Null()]))
		})
	)
});

async function changeAddress(
	cookie: string,
	id: string,
	body: Record<string, unknown>
) {
	const response = await app.handle(
		new Request(`http://e.ly/admin/api/projects/${id}/address`, {
			method: 'POST',
			redirect: 'manual',
			headers: { 'content-type': 'application/json', cookie },
			body: JSON.stringify(body)
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		body: text
			? shaped(Type.Record(Type.String(), Type.Unknown()), JSON.parse(text))
			: {}
	};
}

async function movableBucket(slug: string) {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `Movable ${slug}`,
		slug
	});
	return bucket._id;
}

/**
 * @proves Moving a bucket is an operation of its own: it names what it will break before it breaks it,
 * completes only on a separate confirmation of what was previewed, leaves the previous address answering
 * nothing, and is refused outright for a bucket served at the root. An owner of the bucket's group may
 * correct its path while nothing depends on it; a hostname, or a bucket something depends on, stays a
 * super administrator's.
 */
describe('moving a bucket to a different address (US3)', () => {
	let superCookie: string;
	let counter = 0;

	beforeEach(async () => {
		await ensureAdminSeed();
		forgetBucketAddresses();
		superCookie = await cookieFor('super');
		counter += 1;
	});

	it('names each application, connection, provider with its new callback, and resource, before an address changes', async () => {
		const slug = `preview-${counter}`;
		const id = await movableBucket(slug);
		const { view } = await createClient(id, {
			clientId: `billing-${nanoid()}`,
			clientName: 'Billing',
			grantTypes: ['authorization_code'],
			redirectUris: ['https://billing.example.com/cb'],
			tokenEndpointAuthMethod: 'none'
		});
		await getBucketStore().update(id, { federation: [provider('corp')] });
		const connection = await getProvisioningConnectionStore().create({
			_id: nanoid(),
			bucketId: id,
			displayName: 'Directory',
			enabled: true,
			providerId: 'corp',
			correlation: { claim: 'oid', attribute: 'externalId' },
			emailTrust: 'untrusted',
			oauthCredential: null
		});
		const identifier = `https://api-${String(counter)}-${nanoid()
			.toLowerCase()
			.replace(/[^a-z0-9]/g, '')}.example.com/mcp`;
		await getProtectedResourceStore().create({
			namespace: id,
			identifier,
			bucketId: id,
			name: 'API',
			scopes: ['read']
		});

		const { status, body } = await changeAddress(superCookie, id, {
			host: `preview-${counter}.e.ly`
		});
		const preview = shaped(Preview, body);

		/* Named rather than counted: "4 things" tells an operator nothing they can act on, and each of these
		 * is what they take to whoever owns it. */
		expect(status).toBe(409);
		expect(preview.applications).toEqual([
			{ clientId: view.clientId, name: 'Billing' }
		]);
		expect(preview.connections).toEqual([
			{ id: connection._id, displayName: 'Directory' }
		]);
		expect(preview.providers).toEqual([
			{
				id: 'corp',
				displayName: 'corp',
				newCallback: `http://preview-${counter}.e.ly/federation/callback`
			}
		]);
		expect(preview.resources).toEqual([{ identifier, name: 'API' }]);
		expect([preview.from, preview.to]).toEqual([
			`http://e.ly/${slug}`,
			`http://preview-${counter}.e.ly`
		]);
	});

	it('refuses a commit whose expectation no longer matches, with the fresh preview', async () => {
		const id = await movableBucket(`stale-${counter}`);
		const { body } = await changeAddress(superCookie, id, {
			slug: `stale-moved-${counter}`
		});
		const seen = shaped(Preview, body).expect;
		/* A provider configured while the preview was open: the consent given did not cover it. */
		await getBucketStore().update(id, { federation: [provider('late')] });

		const { status, body: refused } = await changeAddress(superCookie, id, {
			slug: `stale-moved-${counter}`,
			confirm: true,
			expect: seen
		});

		expect(status).toBe(409);
		expect(shaped(Preview, refused).providers.map((p) => p.id)).toEqual([
			'late'
		]);
		expect((await getBucketStore().find(id))?.slug).toBe(`stale-${counter}`);
	});

	it('refuses a commit that does not carry the counts of the preview it confirms', async () => {
		const id = await movableBucket(`blind-${counter}`);

		const { status } = await changeAddress(superCookie, id, {
			slug: `blind-moved-${counter}`,
			confirm: true
		});

		expect(status).toBe(409);
		expect((await getBucketStore().find(id))?.slug).toBe(`blind-${counter}`);
	});

	it('refuses to complete an address change without a separate confirmation', async () => {
		const id = await movableBucket(`unconfirmed-${counter}`);

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
		const id = await movableBucket(`raced-${counter}`);
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
				confirm: true,
				expect: NOTHING
			});

			expect(status).toBe(409);
		} finally {
			lookup.mockRestore();
		}
	});

	it('changes the issuer identifier when the change is confirmed', async () => {
		const id = await movableBucket(`moved-${counter}`);
		const host = `moved-${counter}.e.ly`;

		const { status } = await changeAddress(superCookie, id, {
			host,
			confirm: true,
			expect: NOTHING
		});
		expect(status).toBe(200);

		const after = await getBucketStore().find(id);
		expect(after?.host).toBe(host);
		expect(issuerFor(present(after, 'after'))).toBe(`http://${host}`);
	});

	it('stops answering at the previous address once the change is confirmed', async () => {
		const slug = `vacated-${counter}`;
		const id = await movableBucket(slug);

		await changeAddress(superCookie, id, {
			host: `vacated-${counter}.e.ly`,
			confirm: true,
			expect: NOTHING
		});
		forgetBucketAddresses();

		/* An old address that quietly keeps working is a second issuer identifier for one population,
		 * which is the one thing an issuer identifier may not have. */
		expect(await getBucketStore().findBySlug(slug)).toBeNull();
	});

	it('reports one address for a bucket, never two', async () => {
		const id = await movableBucket(`single-${counter}`);

		await changeAddress(superCookie, id, {
			host: `single-${counter}.e.ly`,
			confirm: true,
			expect: NOTHING
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

	describe('by an owner of the bucket’s group', () => {
		let ownerCookie: string;
		let groupId: string;

		beforeEach(async () => {
			const owner = await createAdministrator('plain');
			ownerCookie = await sessionCookie(owner);
			groupId = await personalGroupId(owner._id);
		});

		async function ownBucket(slug: string) {
			return getBucketStore().create({
				ownerGroupId: groupId,
				name: `Own ${slug}`,
				slug
			});
		}

		it('corrects a mistyped path on a bucket nothing uses, and the trail says from which address to which', async () => {
			const bucket = await ownBucket(`mistpyed-${counter}`);

			const preview = await changeAddress(ownerCookie, bucket._id, {
				slug: `mistyped-${counter}`
			});
			const committed = await changeAddress(ownerCookie, bucket._id, {
				slug: `mistyped-${counter}`,
				confirm: true,
				expect: shaped(Preview, preview.body).expect
			});
			const trail = await app.handle(
				new Request(
					`http://e.ly/admin/api/audit?targetId=${encodeURIComponent(bucket._id)}`,
					{ headers: { cookie: ownerCookie } }
				)
			);

			expect(committed.status).toBe(200);
			expect((await getBucketStore().find(bucket._id))?.slug).toBe(
				`mistyped-${counter}`
			);
			const entry = shaped(AuditPage, await trail.json()).entries.find(
				(e) => e.action === 'project.address.change'
			);
			expect(entry).toMatchObject({
				from: issuerFor({ _id: bucket._id, slug: `mistpyed-${counter}` }),
				to: issuerFor({ _id: bucket._id, slug: `mistyped-${counter}` })
			});
		});

		it('refuses an owner a hostname for a bucket nothing uses', async () => {
			const bucket = await ownBucket(`unhosted-${counter}`);

			const { status } = await changeAddress(ownerCookie, bucket._id, {
				host: `unhosted-${counter}.e.ly`,
				confirm: true,
				expect: NOTHING
			});

			expect(status).toBe(403);
			expect((await getBucketStore().find(bucket._id))?.host).toBeUndefined();
		});

		it('refuses an owner once an application belongs to the bucket, and says what depends on it', async () => {
			const bucket = await ownBucket(`used-${counter}`);
			await createClient(bucket._id, {
				clientId: `uses-${nanoid()}`,
				clientName: `Uses ${counter}`,
				grantTypes: ['authorization_code'],
				redirectUris: ['https://uses.example.com/cb'],
				tokenEndpointAuthMethod: 'none'
			});

			const { status, body } = await changeAddress(ownerCookie, bucket._id, {
				slug: `used-moved-${counter}`,
				confirm: true,
				expect: NOTHING
			});

			expect(status).toBe(403);
			expect(body.message).toBe(
				"Used by 1 application, 0 identity providers and 0 provisioning connections: only an instance administrator can change this project's address now."
			);
			expect((await getBucketStore().find(bucket._id))?.slug).toBe(
				`used-${counter}`
			);
		});
	});

	it('refuses a plain member of the group a bucket nothing uses belongs to', async () => {
		const owner = await createAdministrator('plain');
		const member = await createAdministrator('plain');
		const team = await regularGroup([owner], [member]);
		const bucket = await getBucketStore().create({
			ownerGroupId: team._id,
			name: `Team ${counter}`,
			slug: `team-${counter}`
		});

		const { status } = await changeAddress(
			await sessionCookie(member),
			bucket._id,
			{ slug: `team-moved-${counter}`, confirm: true, expect: NOTHING }
		);

		expect(status).toBe(403);
		expect((await getBucketStore().find(bucket._id))?.slug).toBe(
			`team-${counter}`
		);
	});

	it('refuses a caller who is not a super administrator alike for a missing bucket and a forbidden one', async () => {
		const outsider = await cookieFor('plain');
		const forbidden = await movableBucket(`forbidden-${counter}`);

		const missing = await changeAddress(outsider, `missing-${counter}`, {
			slug: `missing-moved-${counter}`
		});
		const refused = await changeAddress(outsider, forbidden, {
			slug: `forbidden-moved-${counter}`
		});

		expect(refused.status).toBe(403);
		expect([missing.status, missing.body.message]).toEqual([
			refused.status,
			refused.body.message
		]);
	});
});
