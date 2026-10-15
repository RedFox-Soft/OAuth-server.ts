import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterAll
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import { adminApiRoutes } from 'lib/admin/routes.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getSmtpSettingsStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { SmtpSettings } from 'lib/adapters/types.ts';
import { ADMIN_SESSION_COOKIE, UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { sessionFor } from '../admin_session.ts';
import { createAdministrator } from '../administrators.ts';
import { emailsTo, resetSentEmails } from '../mail_capture.ts';
import { present, shaped } from '../shape.ts';

const MAIL: SmtpSettings = {
	host: 'smtp.example.test',
	port: 587,
	secure: false,
	username: '',
	password: '',
	fromName: 'Accounts',
	fromEmail: 'accounts@example.test'
};
// The store has no delete; an empty host is what "not configured" means to the mailer.
const NO_MAIL: SmtpSettings = { ...MAIL, host: '', fromEmail: '' };

let cookie: string;

async function call(
	method: 'GET' | 'POST',
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

async function bucket(emailVerificationRequired = false) {
	const created = await getBucketStore().create({
		name: `ce-${Math.random()}`,
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	if (emailVerificationRequired) {
		await getBucketStore().update(created._id, {
			emailVerificationRequired: true
		});
	}
	return created._id;
}

const Person = Type.Object({
	_id: Type.String(),
	email: Type.String(),
	verified: Type.Boolean()
});

async function auditedAs(action: string, targetId: string) {
	return (await adminAuditStore.list({ action, targetId })).entries;
}

/**
 * @proves An administrator creates a person with or without a password under the bucket's verification
 * policy, changes their address — refused when another account or a directory holds it, with nothing
 * recorded — and mails them a fresh verification message that never reaches the administrator.
 */
describe('creating a bucket user and changing their address', () => {
	let previousMail: SmtpSettings | null = null;

	beforeAll(async () => {
		await ensureAdminSeed();
		const admin = await createAdministrator('super');
		cookie = `${ADMIN_SESSION_COOKIE}=${(await sessionFor(admin))._id}`;
		previousMail = await getSmtpSettingsStore().get();
	});

	beforeEach(async () => {
		resetSentEmails();
		await getSmtpSettingsStore().set(MAIL);
	});

	afterAll(async () => {
		await getSmtpSettingsStore().set(previousMail ?? NO_MAIL);
	});

	it('creates a person without a password, whom no password opens', async () => {
		const b = await bucket();

		const { status, body } = await call(
			'POST',
			`/admin/api/projects/${b}/users`,
			{
				email: 'federated@example.com'
			}
		);

		expect(status).toBe(201);
		expect(body).toHaveProperty('passwordSet', false);
	});

	it('creates a person unverified when the bucket requires verification', async () => {
		const b = await bucket(true);

		const { body } = await call('POST', `/admin/api/projects/${b}/users`, {
			email: 'unproven@example.com',
			password: 'a long enough password'
		});

		expect(shaped(Person, body).verified).toBe(false);
	});

	it('changes a person’s address and leaves the new one unverified', async () => {
		const b = await bucket();
		const user = await getUserStore(b).create('old@example.com', 'h', true);

		const { status, body } = await call(
			'POST',
			`/admin/api/projects/${b}/users/${user._id}/email`,
			{ email: 'New@Example.com' }
		);

		expect(status).toBe(200);
		const person = shaped(Person, body);
		expect(person.email).toBe('new@example.com');
		expect(person.verified).toBe(false);
	});

	it('records an address change by the field, never the addresses', async () => {
		const b = await bucket();
		const user = await getUserStore(b).create('before@example.com', 'h', true);

		await call('POST', `/admin/api/projects/${b}/users/${user._id}/email`, {
			email: 'after@example.com'
		});

		const [entry] = await auditedAs('enduser.email.change', user._id);
		expect(present(entry, 'an entry').attributes).toEqual(['email']);
		expect(JSON.stringify(entry)).not.toContain('example.com');
	});

	it('refuses an address another account holds, on the email field, and records nothing', async () => {
		const b = await bucket();
		await getUserStore(b).create('taken@example.com', 'h', true);
		const user = await getUserStore(b).create('mover@example.com', 'h', true);

		const { status, body } = await call(
			'POST',
			`/admin/api/projects/${b}/users/${user._id}/email`,
			{ email: 'TAKEN@example.com' }
		);

		expect(status).toBe(409);
		expect(body).toHaveProperty('field', 'email');
		expect(await auditedAs('enduser.email.change', user._id)).toEqual([]);
	});

	it('refuses to change the address of a directory’s person, naming the connection', async () => {
		const b = await bucket();
		const user = await getUserStore(b).create('dir@example.com', 'h', true);
		await getUserStore(b).update(user._id, { provisionedBy: 'conn-hr' });

		const { status, body } = await call(
			'POST',
			`/admin/api/projects/${b}/users/${user._id}/email`,
			{ email: 'elsewhere@example.com' }
		);

		expect(status).toBe(409);
		expect(
			shaped(Type.Object({ message: Type.String() }), body).message
		).toContain('conn-hr');
	});

	it('answers 404 when changing the address of a person the bucket does not hold', async () => {
		const b = await bucket();

		const { status } = await call(
			'POST',
			`/admin/api/projects/${b}/users/absent-user/email`,
			{ email: 'nobody@example.com' }
		);

		expect(status).toBe(404);
	});

	it('mails an unverified person a verification message and answers without its link', async () => {
		const b = await bucket();
		const user = await getUserStore(b).create('resend@example.com', 'h', false);

		const { status, body } = await call(
			'POST',
			`/admin/api/projects/${b}/users/${user._id}/verification`
		);

		expect(status).toBe(204);
		expect(body).toBeUndefined();
		expect(emailsTo('resend@example.com')).toHaveLength(1);
	});

	it('refuses to send to an address that is already verified', async () => {
		const b = await bucket();
		const user = await getUserStore(b).create('done@example.com', 'h', true);

		const { status } = await call(
			'POST',
			`/admin/api/projects/${b}/users/${user._id}/verification`
		);

		expect(status).toBe(409);
		expect(emailsTo('done@example.com')).toHaveLength(0);
	});

	it('refuses to send while mail delivery is not configured, and records nothing', async () => {
		const b = await bucket();
		const user = await getUserStore(b).create('nomail@example.com', 'h', false);
		await getSmtpSettingsStore().set(NO_MAIL);

		const { status, body } = await call(
			'POST',
			`/admin/api/projects/${b}/users/${user._id}/verification`
		);

		expect(status).toBe(409);
		expect(body).toHaveProperty('message');
		expect(await auditedAs('enduser.verification.send', user._id)).toEqual([]);
	});

	it('refuses a second message sent straight after the first', async () => {
		const b = await bucket();
		const user = await getUserStore(b).create('twice@example.com', 'h', false);
		await call(
			'POST',
			`/admin/api/projects/${b}/users/${user._id}/verification`
		);

		const { status } = await call(
			'POST',
			`/admin/api/projects/${b}/users/${user._id}/verification`
		);

		expect(status).toBe(429);
		expect(emailsTo('twice@example.com')).toHaveLength(1);
	});
});
