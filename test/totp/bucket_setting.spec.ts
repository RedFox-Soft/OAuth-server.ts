import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	adminAuditStore,
	getBucketStore,
	getProjectStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import type { UserBucket } from 'lib/adapters/types.ts';

const app = new Elysia().use(resolveAdmin).use(bucketRoutes);
const client = treaty(app);

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

async function sessionCookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${unique(roles.join('-'))}@x.io`,
		'hash',
		roles
	);
	const session = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return { cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`, userId: user._id };
}

async function superCookie() {
	return (await sessionCookieFor(['super_admin'])).cookie;
}

describe('bucket sign-in method setting', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('defaults a newly created bucket to not requiring the second factor', async () => {
		const cookie = await superCookie();
		const res = await client.admin.api.buckets.post(
			{ name: unique('Defaults') },
			{ headers: { cookie } }
		);
		expect((res.data as UserBucket).totpRequired).toBe(false);
	});

	// A bucket document written before this field existed holds no value for it. Reading it back as
	// undefined would be falsy and therefore accidentally correct — but only accidentally, and the
	// same shape closed the password door on every existing bucket once before. The read must default.
	it('reads a bucket that predates the field as not requiring it', async () => {
		const cookie = await superCookie();
		const bucket = await getBucketStore().create({ name: unique('Legacy') });

		// The in-memory store hands back the live record, so this is the stored document losing a field.
		delete (bucket as Partial<UserBucket>).totpRequired;

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.get({ headers: { cookie } });
		expect(res.status).toBe(200);
		expect((res.data as UserBucket).totpRequired).toBe(false);
	});

	it('accepts the setting at creation', async () => {
		const cookie = await superCookie();
		const res = await client.admin.api.buckets.post(
			{ name: unique('Strict'), totpRequired: true },
			{ headers: { cookie } }
		);
		expect((res.data as UserBucket).totpRequired).toBe(true);
	});

	it('persists a change and leaves every other bucket alone', async () => {
		const cookie = await superCookie();
		const first = (
			await client.admin.api.buckets.post(
				{ name: unique('First') },
				{ headers: { cookie } }
			)
		).data as UserBucket;
		const second = (
			await client.admin.api.buckets.post(
				{ name: unique('Second') },
				{ headers: { cookie } }
			)
		).data as UserBucket;

		const patched = await client.admin.api
			.buckets({ id: first._id })
			.patch({ totpRequired: true }, { headers: { cookie } });
		expect(patched.status).toBe(200);
		expect((patched.data as UserBucket).totpRequired).toBe(true);

		const untouched = await client.admin.api
			.buckets({ id: second._id })
			.get({ headers: { cookie } });
		expect((untouched.data as UserBucket).totpRequired).toBe(false);

		// And it survives a read, rather than only appearing in the patch response.
		expect((await getBucketStore().find(first._id))?.totpRequired).toBe(true);
	});

	it('turns the requirement back off', async () => {
		const cookie = await superCookie();
		const bucket = (
			await client.admin.api.buckets.post(
				{ name: unique('Toggling'), totpRequired: true },
				{ headers: { cookie } }
			)
		).data as UserBucket;

		const patched = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ totpRequired: false }, { headers: { cookie } });
		expect((patched.data as UserBucket).totpRequired).toBe(false);
	});

	/*
	 * Permitted but inert, and the operator is told so. Refusing would be wrong: recording the intended
	 * posture before opening the password door is a reasonable order to do things in.
	 */
	it('advises, rather than refuses, when password sign-in is off', async () => {
		const cookie = await superCookie();
		const bucket = (
			await client.admin.api.buckets.post(
				{ name: unique('Federated') },
				{ headers: { cookie } }
			)
		).data as UserBucket;

		// A provider has to exist before password login can be switched off, or the lockout guard refuses.
		await getBucketStore().update(bucket._id, {
			passwordLogin: false,
			federation: [
				{
					id: 'acme',
					displayName: 'Acme',
					issuer: 'https://idp.example.com',
					clientId: 'x',
					clientSecret: 'y',
					scopes: ['openid'],
					enabled: true,
					provisioning: 'jit',
					emailTrusted: true,
					allowedEmailDomains: [],
					emailClaim: 'email'
				}
			]
		});

		const patched = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ totpRequired: true }, { headers: { cookie } });

		expect(patched.status).toBe(200);
		expect((patched.data as UserBucket).totpRequired).toBe(true);
		expect((patched.data as { advisory?: string }).advisory).toContain(
			'passwordLogin'
		);
	});

	it('carries no advisory when password sign-in is on', async () => {
		const cookie = await superCookie();
		const bucket = (
			await client.admin.api.buckets.post(
				{ name: unique('Normal') },
				{ headers: { cookie } }
			)
		).data as UserBucket;

		const patched = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ totpRequired: true }, { headers: { cookie } });
		expect((patched.data as { advisory?: string }).advisory).toBeUndefined();
	});

	it('refuses a caller with no rights over the bucket, changing nothing', async () => {
		const cookie = await superCookie();
		const outsider = await sessionCookieFor(['project_admin']);
		const bucket = (
			await client.admin.api.buckets.post(
				{ name: unique('NotYours') },
				{ headers: { cookie } }
			)
		).data as UserBucket;

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ totpRequired: true }, { headers: { cookie: outsider.cookie } });

		expect(res.status).toBe(403);
		expect((await getBucketStore().find(bucket._id))?.totpRequired).toBe(false);
	});

	it('refuses an unauthenticated caller', async () => {
		const cookie = await superCookie();
		const bucket = (
			await client.admin.api.buckets.post(
				{ name: unique('Anon') },
				{ headers: { cookie } }
			)
		).data as UserBucket;

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ totpRequired: true });

		expect(res.status).toBe(401);
		expect((await getBucketStore().find(bucket._id))?.totpRequired).toBe(false);
	});

	/*
	 * The trail records the actor and which field was exercised, and deliberately not the values —
	 * entries carry field *names* only, which is what makes "no secret can reach the trail" a
	 * structural property rather than a redaction rule every future call site has to remember
	 * (test/admin/audit_secrecy.spec.ts). The value is recoverable anyway: the bucket holds the
	 * current one and the ordered entries naming this field give every flip since the `false` default.
	 */
	it('records the change against the actor, naming the field and not its value', async () => {
		const admin = await sessionCookieFor(['super_admin']);
		const bucket = (
			await client.admin.api.buckets.post(
				{ name: unique('Audited') },
				{ headers: { cookie: admin.cookie } }
			)
		).data as UserBucket;

		await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ totpRequired: true }, { headers: { cookie: admin.cookie } });

		const { entries } = await adminAuditStore.list({
			targetType: 'UserBucket',
			targetId: bucket._id
		});
		const update = entries.find((entry) => entry.action === 'bucket.update');
		expect(update).toBeDefined();
		expect(update?.actorId).toBe(admin.userId);
		// Flattened onto the entry, not nested under a `detail` object — the store's shape.
		expect(update?.attributes).toContain('totpRequired');
		expect(update?.timestamp).toBeDefined();
		// No from/to pair anywhere in the entry.
		expect(JSON.stringify(update)).not.toContain('"to"');
		expect(JSON.stringify(update)).not.toContain('"from"');
	});

	// The requirement narrows a door; it does not remove one. The lockout guard is about a bucket with
	// no way in at all, and must not start refusing a bucket that simply asks for more proof.
	it('does not engage the no-way-to-sign-in guard', async () => {
		const cookie = await superCookie();
		const bucket = (
			await client.admin.api.buckets.post(
				{ name: unique('StillReachable'), totpRequired: true },
				{ headers: { cookie } }
			)
		).data as UserBucket;
		expect(bucket.totpRequired).toBe(true);
		expect(bucket.passwordLogin).toBe(true);
	});

	it('keeps the setting out of a project-scoped manager they do not manage', async () => {
		const cookie = await superCookie();
		const manager = await sessionCookieFor(['project_admin']);
		const bucket = await getBucketStore().create({
			name: unique('Managed'),
			managedBy: [manager.userId]
		});
		const project = await getProjectStore().create({
			name: unique('Proj'),
			slug: unique('proj'),
			managedBy: [manager.userId]
		});
		await getProjectStore().update(project._id, { bucketId: bucket._id });

		// A project admin may read the bucket their project points at, and must see the setting.
		const read = await client.admin.api
			.buckets({ id: bucket._id })
			.get({ headers: { cookie: manager.cookie } });
		expect(read.status).toBe(200);
		expect((read.data as UserBucket).totpRequired).toBe(false);
		expect(cookie).toBeTruthy();
	});
});
