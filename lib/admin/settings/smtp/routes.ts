import { Elysia } from 'elysia';
import { getSmtpSettingsStore } from '../../../adapters/index.js';
import type { SmtpSettings } from '../../../adapters/types.js';
import {
	assertAuth,
	assertRole,
	AdminError,
	resolveAdmin,
	type AdminContext
} from '../../auth/rbac.js';
import { recordAdminAudit } from '../../audit/record.js';
import { UpdateSmtpBody, SMTP_PASSWORD_MASK } from './schema.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// The client-facing view: the password is never returned, only whether one is stored.
function present(settings: SmtpSettings | null) {
	if (!settings) {
		return {
			host: '',
			port: 587,
			secure: false,
			username: '',
			password: '',
			fromName: '',
			fromEmail: '',
			configured: false
		};
	}
	return {
		host: settings.host,
		port: settings.port,
		secure: settings.secure,
		username: settings.username,
		password: settings.password ? SMTP_PASSWORD_MASK : '',
		fromName: settings.fromName,
		fromEmail: settings.fromEmail,
		configured: true
	};
}

export const smtpSettingsRoutes = new Elysia({ name: 'admin-settings-smtp' })
	.use(resolveAdmin)
	.onError(({ error, set }) => {
		if (error instanceof AdminError) {
			set.status = error.status;
			return { error: 'admin_error', message: error.message };
		}
	})
	.get('/admin/api/settings/smtp', async ({ admin }) => {
		const ctx = assertAuth(admin as AdminContext | null);
		assertRole(ctx, 'super_admin');
		return present(await getSmtpSettingsStore().get());
	})
	.put(
		'/admin/api/settings/smtp',
		async ({ admin, body }) => {
			const ctx = assertAuth(admin as AdminContext | null);
			assertRole(ctx, 'super_admin');

			if (!body.host.trim()) throw new AdminError(422, 'host is required');
			if (!EMAIL_RE.test(body.fromEmail)) {
				throw new AdminError(422, 'fromEmail must be a valid email address');
			}
			if (!Number.isInteger(body.port) || body.port < 1 || body.port > 65535) {
				throw new AdminError(422, 'port must be between 1 and 65535');
			}

			const store = getSmtpSettingsStore();
			const existing = await store.get();
			// The masked sentinel (or an empty value) means "keep the stored password".
			const password =
				body.password && body.password !== SMTP_PASSWORD_MASK
					? body.password
					: (existing?.password ?? '');

			await recordAdminAudit(
				ctx,
				'smtp.settings.update',
				'SmtpSettings',
				'smtp'
			);
			await store.set({
				host: body.host,
				port: body.port,
				secure: body.secure,
				username: body.username,
				password,
				fromName: body.fromName,
				fromEmail: body.fromEmail
			});
			return present(await store.get());
		},
		{ body: UpdateSmtpBody }
	);
