import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { adminSetup } from 'lib/admin/auth/setup.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { adminUserRoutes } from 'lib/admin/users/routes.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { endUserRoutes } from 'lib/admin/users-end/routes.ts';
import { settingsRoutes } from 'lib/admin/settings/routes.ts';
import { smtpSettingsRoutes } from 'lib/admin/settings/smtp/routes.ts';
import { jwksRoutes } from 'lib/admin/jwks/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	adminSessionStore,
	getUserStore,
	getProjectStore,
	getBucketStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import type { AdminAuditEntry } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import {
	BOOTSTRAP_ACTOR,
	SETTINGS_TARGET_ID,
	SMTP_TARGET_ID
} from 'lib/consts/admin_audit_routes.ts';

/*
 * One audit entry per state-changing admin operation — all 23 of them, driven through the real HTTP
 * layer. The companion spec (audit_route_classification) proves nothing was forgotten; this one proves
 * each handler actually writes, with the right action, target and scope.
 *
 * Assertions are scoped by the entity's own id, never by a total count: the in-memory trail is a
 * process-wide singleton, it is append-only, and earlier admin specs in the same `bun test` process
 * have already written to it. The two singleton-configuration operations have no entity id, so those
 * two measure a delta instead.
 *
 * Fixtures (projects, buckets, target admins) are created through the stores rather than the API
 * wherever they are not the operation under test, so "exactly one entry for this id" stays meaningful.
 */
const app = new Elysia()
	.use(resolveAdmin)
	.use(adminSetup)
	.use(projectRoutes)
	.use(clientRoutes)
	.use(adminUserRoutes)
	.use(bucketRoutes)
	.use(endUserRoutes)
	.use(settingsRoutes)
	.use(smtpSettingsRoutes)
	.use(jwksRoutes);

const client = treaty(app);

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

async function superCookie() {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${unique('super')}@x.io`,
		'hash',
		['super_admin']
	);
	const session = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return {
		cookie: `${ADMIN_SESSION_COOKIE}=${session._id}`,
		userId: user._id,
		email: user.email
	};
}

async function entriesFor(targetId: string): Promise<AdminAuditEntry[]> {
	// An undefined filter means "no constraint" to the store, so a target id that failed to resolve
	// would quietly match the whole trail instead of failing here.
	expect(typeof targetId).toBe('string');
	expect(targetId.length).toBeGreaterThan(0);
	const { entries } = await adminAuditStore.list({ targetId });
	return entries;
}

// The one entry for this target, asserted to be the only one.
async function soleEntry(targetId: string): Promise<AdminAuditEntry> {
	const entries = await entriesFor(targetId);
	expect(entries).toHaveLength(1);
	return entries[0]!;
}

function expectEntry(
	entry: AdminAuditEntry,
	expected: {
		action: string;
		targetType: string;
		actorId: string;
		targetScope?: string | null;
		attributes?: string[];
	}
) {
	expect(entry.action).toBe(expected.action);
	expect(entry.targetType).toBe(expected.targetType);
	expect(entry.actorId).toBe(expected.actorId);
	expect(entry.actorEmail).toBeTruthy();
	expect(entry.timestamp).toBeInstanceOf(Date);
	// Set only where the target id does not resolve on its own; null everywhere else.
	expect(entry.targetScope ?? null).toBe(expected.targetScope ?? null);
	// Names of the fields the request set, sorted; empty where the operation has no field list of its
	// own and the action name carries the whole meaning.
	expect(entry.attributes ?? []).toEqual(expected.attributes ?? []);
}

async function makeProject() {
	return getProjectStore().create({ name: 'P', slug: unique('p') });
}

async function makeBucket() {
	return getBucketStore().create({ name: 'B' });
}

const CLIENT_BODY = {
	grantTypes: ['authorization_code' as const],
	tokenEndpointAuthMethod: 'client_secret_basic' as const,
	redirectUris: ['https://rp.example.com/cb']
};

/*
 * First-run setup runs before anything else in this file and against a deliberately emptied admin
 * bucket: the route closes itself as soon as one super_admin exists, and earlier specs in this process
 * have seeded several.
 */
describe('admin audit coverage: bootstrap', () => {
	it('records the first-run setup against the unauthenticated bootstrap actor', async () => {
		resetAdminMemoryStores();

		const email = `${unique('boot')}@x.io`;
		const res = await client.admin.api.setup.post({
			email,
			password: 'a-long-enough-password'
		});
		expect(res.status).toBe(201);

		const created = await getUserStore(ADMIN_BUCKET_ID).findByEmail(email);
		expect(created).not.toBeNull();

		const entry = await soleEntry(created!._id);
		expectEntry(entry, {
			action: 'setup.bootstrap',
			targetType: 'AdminUser',
			actorId: BOOTSTRAP_ACTOR
		});
		// No '@' and a colon: unmistakably not a real administrator, without a lookup.
		expect(entry.actorEmail).toBe(BOOTSTRAP_ACTOR);
		expect(entry.actorEmail).not.toContain('@');
	});
});

describe('admin audit coverage: projects', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('records a project creation against the id the project will have', async () => {
		const { cookie, userId } = await superCookie();

		const res = await client.admin.api.projects.post(
			{ name: 'Audited', slug: unique('audited') },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(201);
		const created = res.data as { _id: string };

		expectEntry(await soleEntry(created._id), {
			action: 'project.create',
			targetType: 'Project',
			actorId: userId
		});
	});

	it('records a project update', async () => {
		const { cookie, userId } = await superCookie();
		const project = await makeProject();

		const res = await client.admin.api
			.projects({ id: project._id })
			.patch({ name: 'Renamed' }, { headers: { cookie } });
		expect(res.status).toBe(200);

		expectEntry(await soleEntry(project._id), {
			action: 'project.update',
			targetType: 'Project',
			actorId: userId,
			attributes: ['name']
		});
	});

	it('records a project deletion', async () => {
		const { cookie, userId } = await superCookie();
		const project = await makeProject();

		const res = await client.admin.api
			.projects({ id: project._id })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);

		expectEntry(await soleEntry(project._id), {
			action: 'project.delete',
			targetType: 'Project',
			actorId: userId
		});
	});

	it('records a bucket assignment', async () => {
		const { cookie, userId } = await superCookie();
		const project = await makeProject();
		const bucket = await makeBucket();

		const res = await client.admin.api
			.projects({ id: project._id })
			.bucket.put({ bucketId: bucket._id }, { headers: { cookie } });
		expect(res.status).toBe(200);

		expectEntry(await soleEntry(project._id), {
			action: 'project.bucket.assign',
			targetType: 'Project',
			actorId: userId,
			attributes: ['bucketId']
		});
	});
});

describe('admin audit coverage: clients', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('records a client creation against the id the client will have', async () => {
		const { cookie, userId } = await superCookie();
		const project = await makeProject();

		const res = await client.admin.api
			.projects({ id: project._id })
			.clients.post(CLIENT_BODY, { headers: { cookie } });
		expect(res.status).toBe(201);
		const created = res.data as { clientId: string };

		expectEntry(await soleEntry(created.clientId), {
			action: 'client.create',
			targetType: 'Client',
			actorId: userId
		});
	});

	it('records a client update', async () => {
		const { cookie, userId } = await superCookie();
		const project = await makeProject();
		const created = (
			await client.admin.api
				.projects({ id: project._id })
				.clients.post(CLIENT_BODY, { headers: { cookie } })
		).data as { clientId: string };

		const res = await client.admin.api
			.projects({ id: project._id })
			.clients({ clientId: created.clientId })
			.patch({ clientName: 'Renamed' }, { headers: { cookie } });
		expect(res.status).toBe(200);

		// Two entries share this id now — the create and the update — so this one is found by action.
		const { entries } = await adminAuditStore.list({
			targetId: created.clientId,
			action: 'client.update'
		});
		expect(entries).toHaveLength(1);
		expectEntry(entries[0]!, {
			action: 'client.update',
			targetType: 'Client',
			actorId: userId,
			attributes: ['clientName']
		});
	});

	it('records a secret rotation, without the secret', async () => {
		const { cookie, userId } = await superCookie();
		const project = await makeProject();
		const created = (
			await client.admin.api
				.projects({ id: project._id })
				.clients.post(CLIENT_BODY, { headers: { cookie } })
		).data as { clientId: string; secret?: string };

		const res = await client.admin.api
			.projects({ id: project._id })
			.clients({ clientId: created.clientId })
			.secret.post(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);
		const rotated = res.data as { secret: string };

		const { entries } = await adminAuditStore.list({
			targetId: created.clientId,
			action: 'client.secret.rotate'
		});
		expect(entries).toHaveLength(1);
		expectEntry(entries[0]!, {
			action: 'client.secret.rotate',
			targetType: 'Client',
			actorId: userId
		});
		expect(JSON.stringify(entries[0])).not.toContain(rotated.secret);
	});

	it('records a client deletion', async () => {
		const { cookie, userId } = await superCookie();
		const project = await makeProject();
		const created = (
			await client.admin.api
				.projects({ id: project._id })
				.clients.post(CLIENT_BODY, { headers: { cookie } })
		).data as { clientId: string };

		const res = await client.admin.api
			.projects({ id: project._id })
			.clients({ clientId: created.clientId })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);

		const { entries } = await adminAuditStore.list({
			targetId: created.clientId,
			action: 'client.delete'
		});
		expect(entries).toHaveLength(1);
		expectEntry(entries[0]!, {
			action: 'client.delete',
			targetType: 'Client',
			actorId: userId
		});
	});
});

describe('admin audit coverage: administrators', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('records an administrator creation against the id the account will have', async () => {
		const { cookie, userId } = await superCookie();

		const res = await client.admin.api.admins.post(
			{
				email: `${unique('made')}@x.io`,
				password: 'a-long-enough-password',
				roles: ['project_admin']
			},
			{ headers: { cookie } }
		);
		expect(res.status).toBe(201);
		const created = res.data as { _id: string };

		expectEntry(await soleEntry(created._id), {
			action: 'admin.create',
			targetType: 'AdminUser',
			actorId: userId
		});
	});

	it('records an administrator update', async () => {
		const { cookie, userId } = await superCookie();
		const target = await getUserStore(ADMIN_BUCKET_ID).create(
			`${unique('target')}@x.io`,
			'hash',
			['project_admin']
		);

		const res = await client.admin.api
			.admins({ id: target._id })
			.patch({ roles: ['super_admin'] }, { headers: { cookie } });
		expect(res.status).toBe(200);

		expectEntry(await soleEntry(target._id), {
			action: 'admin.update',
			targetType: 'AdminUser',
			actorId: userId,
			attributes: ['roles']
		});
	});

	// The route sets active:false and keeps the row, so the action must not claim a deletion.
	it('records a deactivation as a deactivation, not a deletion', async () => {
		const { cookie, userId } = await superCookie();
		const target = await getUserStore(ADMIN_BUCKET_ID).create(
			`${unique('target')}@x.io`,
			'hash',
			['project_admin']
		);

		const res = await client.admin.api
			.admins({ id: target._id })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);

		expectEntry(await soleEntry(target._id), {
			action: 'admin.deactivate',
			targetType: 'AdminUser',
			actorId: userId
		});
	});
});

describe('admin audit coverage: buckets', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('records a bucket creation against the id the bucket will have', async () => {
		const { cookie, userId } = await superCookie();

		const res = await client.admin.api.buckets.post(
			{ name: 'Audited bucket' },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(201);
		const created = res.data as { _id: string };

		expectEntry(await soleEntry(created._id), {
			action: 'bucket.create',
			targetType: 'UserBucket',
			actorId: userId
		});
	});

	// The gap FR-002 exists to close: this used to be recorded only when a registration or
	// verification field was present.
	it('records a bucket update that touches no policy field', async () => {
		const { cookie, userId } = await superCookie();
		const bucket = await makeBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ name: 'Renamed only' }, { headers: { cookie } });
		expect(res.status).toBe(200);

		expectEntry(await soleEntry(bucket._id), {
			action: 'bucket.update',
			targetType: 'UserBucket',
			actorId: userId,
			attributes: ['name']
		});
	});

	it('records a manager reassignment', async () => {
		const { cookie, userId } = await superCookie();
		const bucket = await makeBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.patch({ managedBy: [userId] }, { headers: { cookie } });
		expect(res.status).toBe(200);

		expectEntry(await soleEntry(bucket._id), {
			action: 'bucket.update',
			targetType: 'UserBucket',
			actorId: userId,
			attributes: ['managedBy']
		});
	});

	it('records a bucket deletion', async () => {
		const { cookie, userId } = await superCookie();
		const bucket = await makeBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);

		expectEntry(await soleEntry(bucket._id), {
			action: 'bucket.delete',
			targetType: 'UserBucket',
			actorId: userId
		});
	});
});

/*
 * The four operations whose target lives in per-bucket storage. Without `targetScope` the entry names
 * an id that cannot be resolved to an account — not even to an email — without searching every bucket.
 */
describe('admin audit coverage: end-users', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('records an end-user creation with its bucket', async () => {
		const { cookie, userId } = await superCookie();
		const bucket = await makeBucket();

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users.post(
				{ email: `${unique('end')}@x.io`, password: 'password-long' },
				{ headers: { cookie } }
			);
		expect(res.status).toBe(201);
		const created = res.data as { _id: string };

		expectEntry(await soleEntry(created._id), {
			action: 'enduser.create',
			targetType: 'EndUser',
			actorId: userId,
			targetScope: bucket._id
		});
	});

	it('records an end-user update with its bucket', async () => {
		const { cookie, userId } = await superCookie();
		const bucket = await makeBucket();
		const target = await getUserStore(bucket._id).create(
			`${unique('end')}@x.io`,
			'hash'
		);

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid: target._id })
			.patch({ active: false }, { headers: { cookie } });
		expect(res.status).toBe(200);

		expectEntry(await soleEntry(target._id), {
			action: 'enduser.update',
			targetType: 'EndUser',
			actorId: userId,
			targetScope: bucket._id,
			attributes: ['active']
		});
	});

	it('records a password reset, without the password', async () => {
		const { cookie, userId } = await superCookie();
		const bucket = await makeBucket();
		const target = await getUserStore(bucket._id).create(
			`${unique('end')}@x.io`,
			'hash'
		);

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid: target._id })
			.password.post(
				{ password: 'brand-new-password' },
				{ headers: { cookie } }
			);
		expect(res.status).toBe(200);

		const entry = await soleEntry(target._id);
		expectEntry(entry, {
			action: 'enduser.password.reset',
			targetType: 'EndUser',
			actorId: userId,
			targetScope: bucket._id
		});
		expect(JSON.stringify(entry)).not.toContain('brand-new-password');
	});

	it('records an end-user deletion with its bucket', async () => {
		const { cookie, userId } = await superCookie();
		const bucket = await makeBucket();
		const target = await getUserStore(bucket._id).create(
			`${unique('end')}@x.io`,
			'hash'
		);

		const res = await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid: target._id })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);

		expectEntry(await soleEntry(target._id), {
			action: 'enduser.delete',
			targetType: 'EndUser',
			actorId: userId,
			targetScope: bucket._id
		});
	});
});

describe('admin audit coverage: keys and settings', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('records key generation and deletion against the kid', async () => {
		const { cookie, userId } = await superCookie();

		const before = await client.admin.api.jwks.get({ headers: { cookie } });
		const beforeKids = new Set(
			(before.data as { keys: { kid: string }[] }).keys.map((k) => k.kid)
		);

		const generated = await client.admin.api.jwks.post(
			{ alg: 'RS256' },
			{ headers: { cookie } }
		);
		expect(generated.status).toBe(200);
		const state = generated.data as { keys: { kid: string }[] };
		// A generated key is hot-applied, so it is active rather than "changed" — the new kid is the one
		// the previous listing did not have.
		const kid = state.keys.find((k) => !beforeKids.has(k.kid))?.kid;
		expect(kid).toBeString();

		expectEntry(await soleEntry(kid!), {
			action: 'jwks.generate',
			targetType: 'jwks',
			actorId: userId
		});

		const removed = await client.admin.api
			.jwks({ kid: kid! })
			.delete(undefined, { headers: { cookie } });
		expect(removed.status).toBe(200);

		const { entries } = await adminAuditStore.list({
			targetId: kid!,
			action: 'jwks.delete'
		});
		expect(entries).toHaveLength(1);
		expectEntry(entries[0]!, {
			action: 'jwks.delete',
			targetType: 'jwks',
			actorId: userId
		});
	});

	/*
	 * The two singleton-configuration operations have no entity id to scope by, so these two measure a
	 * delta around the request instead.
	 */
	it('records a settings update, naming the settings document and the submitted keys', async () => {
		const { cookie, userId } = await superCookie();
		const before = (await adminAuditStore.list({ action: 'settings.update' }))
			.total;

		const res = await client.admin.api.settings.put(
			{ 'revocation.enabled': true, 'par.enabled': true },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(200);

		const { entries, total } = await adminAuditStore.list({
			action: 'settings.update'
		});
		expect(total).toBe(before + 1);
		expectEntry(entries[0]!, {
			action: 'settings.update',
			targetType: 'ApplicationConfig',
			actorId: userId,
			attributes: ['par.enabled', 'revocation.enabled']
		});
		// The key list used to travel here, because the entry had no field for it.
		expect(entries[0]!.targetId).toBe(SETTINGS_TARGET_ID);
	});

	it('records a mail settings update, without the password', async () => {
		const { cookie, userId } = await superCookie();
		const before = (await adminAuditStore.list({ targetId: SMTP_TARGET_ID }))
			.total;

		const res = await client.admin.api.settings.smtp.put(
			{
				host: 'smtp.example.com',
				port: 587,
				secure: false,
				username: 'mailer',
				password: 'super-secret-mail-password',
				fromName: 'OP',
				fromEmail: 'op@example.com'
			},
			{ headers: { cookie } }
		);
		expect(res.status).toBe(200);

		const { entries, total } = await adminAuditStore.list({
			targetId: SMTP_TARGET_ID
		});
		expect(total).toBe(before + 1);
		expectEntry(entries[0]!, {
			action: 'smtp.settings.update',
			targetType: 'SmtpSettings',
			actorId: userId,
			// Names only. `password` appearing here is exactly why values never do.
			attributes: [
				'fromEmail',
				'fromName',
				'host',
				'password',
				'port',
				'secure',
				'username'
			]
		});
		expect(JSON.stringify(entries[0])).not.toContain(
			'super-secret-mail-password'
		);
	});

	/*
	 * Deployments already hold entries written before the field existed. The trail is immutable, so
	 * there is no backfill — only a read-side default, and these must stay readable and filterable.
	 */
	it('reads an entry stored without the field as having no fields set', async () => {
		const targetId = unique('legacy');
		await adminAuditStore.record({
			actorId: 'legacy-actor',
			actorEmail: 'legacy@x.io',
			action: 'settings.update',
			targetType: 'ApplicationConfig',
			targetId
		});

		const entry = await soleEntry(targetId);
		expect(entry.attributes).toEqual([]);
		expect(entry.targetScope).toBeNull();

		const filtered = await adminAuditStore.list({
			action: 'settings.update',
			targetId
		});
		expect(filtered.total).toBe(1);
	});
});
