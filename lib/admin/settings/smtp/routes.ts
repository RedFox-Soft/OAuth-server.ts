import { Elysia } from 'elysia';
import { getSmtpSettingsStore } from '../../../adapters/index.js';
import type { SmtpSettings } from '../../../adapters/types.js';
import {
	assertAuth,
	assertRole,
	AdminError,
	adminErrorBody,
	resolveAdmin,
	type AdminContext
} from '../../auth/rbac.js';
import { recordAdminAudit } from '../../audit/record.js';
import { SMTP_TARGET_ID } from '../../../consts/admin_audit_routes.js';
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
			return adminErrorBody(error);
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
			const next = {
				host: body.host,
				port: body.port,
				secure: body.secure,
				username: body.username,
				password,
				fromName: body.fromName,
				fromEmail: body.fromEmail
			};

			/*
			 * The card is a full replace, so all seven fields arrive on every save. Recording all seven
			 * every time says nothing about what an operator actually did, so the entry names only the
			 * fields whose value moved, and a submission that moves nothing is not an event to record at
			 * all. With no stored record there is nothing configured yet, so then every field is a change.
			 * The password is unaffected by any of this: the mask resolves to the stored secret above, so
			 * keeping it is simply not a change, and only ever its name reaches the trail.
			 */
			const changed = existing
				? (Object.keys(next) as Array<keyof typeof next>).filter(
						(k) => next[k] !== existing[k]
					)
				: Object.keys(next);
			if (changed.length === 0) return present(existing);

			// Field names only — that a password was among them is useful; its value must never be here.
			await recordAdminAudit(ctx, 'smtp.settings.update', SMTP_TARGET_ID, {
				attributes: changed
			});
			await store.set(next);
			return present(await store.get());
		},
		{ body: UpdateSmtpBody }
	);
