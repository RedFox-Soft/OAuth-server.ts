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
import { sessionFor } from '../admin_session.ts';

const app = new Elysia().use(resolveAdmin).use(smtpSettingsRoutes);
const client = treaty(app);

async function cookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const s = await sessionFor(user);
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

	// The card is a full replace, so it submits all seven fields whatever the operator touched. The
	// trail has to describe the edit, not the form.
	it('names only the field that moved, and never the kept password', async () => {
		const cookie = await cookieFor(['super_admin']);
		await client.admin.api.settings.smtp.put(VALID, { headers: { cookie } });

		const res = await client.admin.api.settings.smtp.put(
			{ ...VALID, password: SMTP_PASSWORD_MASK, fromName: 'Renamed' },
			{ headers: { cookie } }
		);

		expect(res.status).toBe(200);
		const { entries } = await adminAuditStore.list({
			targetType: 'SmtpSettings'
		});
		expect(entries[0]?.attributes).toEqual(['fromName']);
	});

	it('records nothing when a resubmitted form changes no field', async () => {
		const cookie = await cookieFor(['super_admin']);
		await client.admin.api.settings.smtp.put(VALID, { headers: { cookie } });
		const before = (await adminAuditStore.list({ targetType: 'SmtpSettings' }))
			.total;

		// Exactly what the card sends after a load and an immediate Save: every field as stored, with
		// the password masked.
		const again = await client.admin.api.settings.smtp.put(
			{ ...VALID, password: SMTP_PASSWORD_MASK },
			{ headers: { cookie } }
		);

		expect(again.status).toBe(200);
		expect(
			(await adminAuditStore.list({ targetType: 'SmtpSettings' })).total
		).toBe(before);
		// Still answered with the stored settings, so the page it refreshes stays correct.
		expect((again.data as Record<string, unknown>).host).toBe(VALID.host);
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
