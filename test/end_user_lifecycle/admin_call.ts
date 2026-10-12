import { adminApiRoutes } from 'lib/admin/routes.ts';
import { getSmtpSettingsStore } from 'lib/adapters/index.ts';
import type { SmtpSettings } from 'lib/adapters/types.ts';

/* The whole admin API as the console reaches it, so every route group answers in its own shape. */
export async function adminCall(
	cookie: string,
	method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
	path: string,
	body?: unknown
): Promise<{ status: number; body: unknown }> {
	const res = await adminApiRoutes.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: {
				cookie,
				...(body === undefined ? {} : { 'content-type': 'application/json' })
			},
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await res.text();
	return {
		status: res.status,
		body: text ? (JSON.parse(text) as unknown) : undefined
	};
}

export const MAIL: SmtpSettings = {
	host: 'smtp.example.test',
	port: 587,
	secure: false,
	username: '',
	password: '',
	fromName: 'Accounts',
	fromEmail: 'accounts@example.test'
};

/* The store has no delete; an empty host is what "not configured" means to the mailer. */
export const NO_MAIL: SmtpSettings = { ...MAIL, host: '', fromEmail: '' };

/*
 * Configures mail for a spec and gives back what was in force, so the spec's `afterAll` can put it back: the
 * settings store is process-wide, and a later spec must not find mail configured because this one ran first.
 */
export async function withMail(): Promise<SmtpSettings | null> {
	const previous = await getSmtpSettingsStore().get();
	await getSmtpSettingsStore().set(MAIL);
	return previous;
}
