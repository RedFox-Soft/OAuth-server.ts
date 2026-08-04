import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { projectRoutes } from 'lib/admin/projects/routes.ts';
import { clientRoutes } from 'lib/admin/clients/routes.ts';
import { bucketRoutes } from 'lib/admin/buckets/routes.ts';
import { endUserRoutes } from 'lib/admin/users-end/routes.ts';
import { adminUserRoutes } from 'lib/admin/users/routes.ts';
import { smtpSettingsRoutes } from 'lib/admin/settings/smtp/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	adminSessionStore,
	getUserStore,
	getProjectStore,
	getBucketStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

/*
 * No secret value may reach the trail — from any operation, in any field.
 *
 * This holds structurally rather than by redaction: entries carry the *names* of the fields a request
 * set and never their values. That is the property under test, because a redaction rule is something a
 * future call site can forget, while "values are never recorded" cannot be forgotten one site at a
 * time. Every operation that handles secret material is driven with a known value and the whole entry
 * is searched for it.
 */
const app = new Elysia()
	.use(resolveAdmin)
	.use(projectRoutes)
	.use(clientRoutes)
	.use(bucketRoutes)
	.use(endUserRoutes)
	.use(adminUserRoutes)
	.use(smtpSettingsRoutes);

const client = treaty(app);

let seq = 0;
const unique = (prefix: string) => `${prefix}-${Date.now()}-${(seq += 1)}`;

const CLIENT_SECRET_MARKER = 'do-not-record-this-client-secret';
const PASSWORD_MARKER = 'do-not-record-this-password-1';
const MAIL_PASSWORD_MARKER = 'do-not-record-this-mail-password';

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
	return `${ADMIN_SESSION_COOKIE}=${session._id}`;
}

// Searches every field of every entry for the target id, serialized — a value hidden in an unexpected
// field is exactly what this is looking for.
async function trailFor(targetId: string): Promise<string> {
	const { entries } = await adminAuditStore.list({ targetId });
	expect(entries.length).toBeGreaterThan(0);
	return JSON.stringify(entries);
}

describe('admin audit secrecy', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('records a client secret rotation without the secret', async () => {
		const cookie = await superCookie();
		const project = await getProjectStore().create({
			name: 'P',
			slug: unique('p')
		});
		const created = (
			await client.admin.api.projects({ id: project._id }).clients.post(
				{
					grantTypes: ['authorization_code'],
					tokenEndpointAuthMethod: 'client_secret_basic',
					redirectUris: ['https://rp.example.com/cb']
				},
				{ headers: { cookie } }
			)
		).data as { clientId: string; secret?: string };

		const rotated = await client.admin.api
			.projects({ id: project._id })
			.clients({ clientId: created.clientId })
			.secret.post(undefined, { headers: { cookie } });
		const { secret } = rotated.data as { secret: string };

		const trail = await trailFor(created.clientId);
		expect(secret).toBeTruthy();
		expect(trail).not.toContain(secret);
		expect(created.secret).toBeTruthy();
		expect(trail).not.toContain(created.secret!);
	});

	it('records an end-user password reset without the password', async () => {
		const cookie = await superCookie();
		const bucket = await getBucketStore().create({ name: 'B' });
		const target = await getUserStore(bucket._id).create(
			`${unique('end')}@x.io`,
			'hash'
		);

		await client.admin.api
			.buckets({ id: bucket._id })
			.users({ uid: target._id })
			.password.post({ password: PASSWORD_MARKER }, { headers: { cookie } });

		const trail = await trailFor(target._id);
		expect(trail).not.toContain(PASSWORD_MARKER);
		// No field names either — the action name already says what happened, so there is nothing for a
		// field list to add. (The action itself contains the word, hence asserting on the list.)
		const { entries } = await adminAuditStore.list({ targetId: target._id });
		expect(entries[0]!.attributes).toEqual([]);
	});

	it('records an end-user creation without the password', async () => {
		const cookie = await superCookie();
		const bucket = await getBucketStore().create({ name: 'B' });

		const created = (
			await client.admin.api
				.buckets({ id: bucket._id })
				.users.post(
					{ email: `${unique('end')}@x.io`, password: PASSWORD_MARKER },
					{ headers: { cookie } }
				)
		).data as { _id: string };

		expect(await trailFor(created._id)).not.toContain(PASSWORD_MARKER);
	});

	it('records an administrator creation without the password', async () => {
		const cookie = await superCookie();

		const created = (
			await client.admin.api.admins.post(
				{
					email: `${unique('made')}@x.io`,
					password: `${PASSWORD_MARKER}-admin`,
					roles: ['project_admin']
				},
				{ headers: { cookie } }
			)
		).data as { _id: string };

		expect(await trailFor(created._id)).not.toContain(PASSWORD_MARKER);
	});

	it('records a mail settings change with the field names but not the password', async () => {
		const cookie = await superCookie();

		await client.admin.api.settings.smtp.put(
			{
				host: 'smtp.example.com',
				port: 587,
				secure: false,
				username: 'mailer',
				password: MAIL_PASSWORD_MARKER,
				fromName: 'OP',
				fromEmail: 'op@example.com'
			},
			{ headers: { cookie } }
		);

		const trail = await trailFor('smtp');
		expect(trail).not.toContain(MAIL_PASSWORD_MARKER);
		// The name is recorded — that a password was among the changed fields is the useful part.
		expect(trail).toContain('password');
	});

	it('records a client creation without the generated secret', async () => {
		const cookie = await superCookie();
		const project = await getProjectStore().create({
			name: 'P',
			slug: unique('p')
		});

		const created = (
			await client.admin.api.projects({ id: project._id }).clients.post(
				{
					clientName: CLIENT_SECRET_MARKER,
					grantTypes: ['authorization_code'],
					tokenEndpointAuthMethod: 'client_secret_basic',
					redirectUris: ['https://rp.example.com/cb']
				},
				{ headers: { cookie } }
			)
		).data as { clientId: string; secret?: string };

		const trail = await trailFor(created.clientId);
		expect(created.secret).toBeTruthy();
		expect(trail).not.toContain(created.secret!);
		// Values of any kind stay out, secret or not: the client name was submitted and is not recorded.
		expect(trail).not.toContain(CLIENT_SECRET_MARKER);
	});
});
