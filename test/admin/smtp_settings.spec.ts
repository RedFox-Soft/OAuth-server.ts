import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { smtpSettingsRoutes } from 'lib/admin/settings/smtp/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminSessionStore,
	adminAuditStore,
	getUserStore,
	getSmtpSettingsStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { SMTP_PASSWORD_MASK } from 'lib/admin/settings/smtp/schema.ts';

const app = new Elysia().use(resolveAdmin).use(smtpSettingsRoutes);
const client = treaty(app);

async function cookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const s = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return `${ADMIN_SESSION_COOKIE}=${s._id}`;
}

const VALID = {
	host: 'smtp.example.com',
	port: 587,
	secure: false,
	username: 'no-reply@example.com',
	password: 's3cret',
	fromName: 'Example',
	fromEmail: 'no-reply@example.com'
};

describe('SMTP settings API', () => {
	beforeEach(async () => {
		await ensureAdminSeed();
	});

	it('stores settings and returns a masked password on GET', async () => {
		const cookie = await cookieFor(['super_admin']);
		const put = await client.admin.api.settings.smtp.put(VALID, {
			headers: { cookie }
		});
		expect(put.status).toBe(200);
		const got = await client.admin.api.settings.smtp.get({
			headers: { cookie }
		});
		const data = got.data as Record<string, unknown>;
		expect(data.host).toBe('smtp.example.com');
		expect(data.password).toBe(SMTP_PASSWORD_MASK);
		expect(data.configured).toBe(true);

		const { entries } = await adminAuditStore.list({
			targetType: 'SmtpSettings'
		});
		expect(entries.some((a) => a.action === 'smtp.settings.update')).toBe(true);
	});

	it('keeps the stored password when the masked sentinel is submitted', async () => {
		const cookie = await cookieFor(['super_admin']);
		await client.admin.api.settings.smtp.put(VALID, { headers: { cookie } });
		await client.admin.api.settings.smtp.put(
			{ ...VALID, password: SMTP_PASSWORD_MASK, fromName: 'Renamed' },
			{ headers: { cookie } }
		);
		const stored = await getSmtpSettingsStore().get();
		expect(stored?.password).toBe('s3cret');
		expect(stored?.fromName).toBe('Renamed');
	});

	it('rejects non-super-admins', async () => {
		const cookie = await cookieFor(['project_admin']);
		const get = await client.admin.api.settings.smtp.get({
			headers: { cookie }
		});
		expect(get.status).toBe(403);
		const put = await client.admin.api.settings.smtp.put(VALID, {
			headers: { cookie }
		});
		expect(put.status).toBe(403);
	});

	it('validates fromEmail and port', async () => {
		const cookie = await cookieFor(['super_admin']);
		const badEmail = await client.admin.api.settings.smtp.put(
			{ ...VALID, fromEmail: 'not-an-email' },
			{ headers: { cookie } }
		);
		expect(badEmail.status).toBe(422);
		const badPort = await client.admin.api.settings.smtp.put(
			{ ...VALID, port: 70000 },
			{ headers: { cookie } }
		);
		expect(badPort.status).toBe(422);
	});
});
