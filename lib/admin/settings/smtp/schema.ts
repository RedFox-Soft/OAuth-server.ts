import { t } from 'elysia';

// Sentinel returned in place of the stored password and accepted back on PUT to mean
// "leave the password unchanged" (so the UI never has to hold the real secret).
export const SMTP_PASSWORD_MASK = '********';

export const UpdateSmtpBody = t.Object({
	host: t.String(),
	port: t.Integer(),
	secure: t.Boolean(),
	username: t.String(),
	password: t.String(),
	fromName: t.String(),
	fromEmail: t.String()
});
