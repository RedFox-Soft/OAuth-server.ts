import { afterAll, beforeAll, describe, expect, it } from 'bun:test';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	adminAuditStore,
	getBucketStore,
	getSmtpSettingsStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { SmtpSettings, User } from 'lib/adapters/types.ts';
import { ADMIN_BUCKET_ID } from 'lib/admin/consts.ts';
import nanoid from 'lib/helpers/nanoid.ts';
import { sentEmails } from 'lib/mail/mailer.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor, regularGroup } from './ownership_fixtures.ts';

async function request(
	method: string,
	path: string,
	cookie: string,
	body?: Readonly<Record<string, unknown>>
): Promise<{ status: number; body: Record<string, unknown> }> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: { 'content-type': 'application/json', cookie },
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		body: text ? (JSON.parse(text) as Record<string, unknown>) : {}
	};
}

const MAIL: SmtpSettings = {
	host: 'smtp.example.test',
	port: 587,
	secure: false,
	username: '',
	password: '',
	fromName: 'Accounts',
	fromEmail: 'accounts@example.test'
};

/**
 * @proves A project's administrators decide whether its people may turn on two-step verification themselves, see
 * whether that is in effect and why not, and cannot offer it on the administrators' project; the person on whose
 * account it is used is told about a removal.
 */
describe('letting people turn on two-step verification themselves', () => {
	let owner: User;
	let cookie: string;
	let superCookie: string;
	let ownerGroupId: string;
	let previousMail: SmtpSettings | null = null;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		owner = await createAdministrator();
		ownerGroupId = (await regularGroup([owner]))._id;
		cookie = await cookieFor(owner);
		superCookie = await cookieFor(await createAdministrator('super'));
		previousMail = await getSmtpSettingsStore().get();
		await getSmtpSettingsStore().set(MAIL);
	});

	afterAll(async () => {
		await getSmtpSettingsStore().set(
			previousMail ?? { ...MAIL, host: '', fromEmail: '' }
		);
	});

	async function project() {
		return getBucketStore().create({
			name: `two-step ${nanoid()}`,
			ownerGroupId
		});
	}

	it('is in effect by default, and off once the administrators turn it off', async () => {
		const bucket = await project();

		const before = await request(
			'GET',
			`/admin/api/projects/${bucket._id}/summary`,
			cookie
		);
		const changed = await request(
			'PATCH',
			`/admin/api/projects/${bucket._id}`,
			cookie,
			{ totpSelfService: false }
		);
		const after = await request(
			'GET',
			`/admin/api/projects/${bucket._id}/summary`,
			cookie
		);

		expect(before.body.twoStepSelfService).toBe('on');
		expect(changed.status).toBe(200);
		expect(changed.body.totpSelfService).toBe(false);
		expect(after.body.twoStepSelfService).toBe('off');
		const { entries } = await adminAuditStore.list({ targetId: bucket._id });
		expect(
			entries.some(
				(entry) =>
					entry.action === 'bucket.update' &&
					entry.attributes?.includes('totpSelfService')
			)
		).toBe(true);
	});

	it('says why it has no effect while password sign-in is off or mail cannot be sent', async () => {
		const bucket = await getBucketStore().create({
			name: `two-step ${nanoid()}`,
			ownerGroupId,
			passwordLogin: false,
			federation: []
		});
		const noPasswords = await request(
			'GET',
			`/admin/api/projects/${bucket._id}/summary`,
			cookie
		);
		const mailBucket = await project();
		await getSmtpSettingsStore().set({ ...MAIL, host: '', fromEmail: '' });
		const noMail = await request(
			'GET',
			`/admin/api/projects/${mailBucket._id}/summary`,
			cookie
		);
		await getSmtpSettingsStore().set(MAIL);

		expect(noPasswords.body.twoStepSelfService).toBe('no_password_login');
		expect(noMail.body.twoStepSelfService).toBe('no_mail');
	});

	it('is refused on the administrators’ project, naming the field', async () => {
		const refused = await request(
			'PATCH',
			`/admin/api/projects/${ADMIN_BUCKET_ID}`,
			superCookie,
			{ totpSelfService: true }
		);

		expect(refused.status).toBe(422);
		expect(JSON.stringify(refused.body)).toContain('totpSelfService');
	});

	it('reports how and whether a person’s factor was set up, and that a removal asks for proof next time', async () => {
		const bucket = await project();
		const users = getUserStore(bucket._id);
		const own = await users.create(`own-${nanoid()}@x.io`, 'h', true);
		await users.update(own._id, {
			totp: {
				secret: 'JBSWY3DPEHPK3PXP',
				enrolledAt: new Date(),
				lastStep: 0,
				via: 'self'
			}
		});
		const older = await users.create(`older-${nanoid()}@x.io`, 'h', true);
		await users.update(older._id, {
			totp: { secret: 'JBSWY3DPEHPK3PXP', enrolledAt: new Date(), lastStep: 0 }
		});

		const ownRead = await request(
			'GET',
			`/admin/api/projects/${bucket._id}/users/${own._id}`,
			cookie
		);
		const olderRead = await request(
			'GET',
			`/admin/api/projects/${bucket._id}/users/${older._id}`,
			cookie
		);
		await request(
			'DELETE',
			`/admin/api/projects/${bucket._id}/users/${own._id}/totp`,
			cookie
		);
		const removedRead = await request(
			'GET',
			`/admin/api/projects/${bucket._id}/users/${own._id}`,
			cookie
		);

		expect(ownRead.body.totpEnrolledVia).toBe('self');
		expect(olderRead.body.totpEnrolledVia).toBe('sign-in');
		expect(removedRead.body.totpEnrolled).toBe(false);
		expect(removedRead.body.totpProofRequired).toBe(true);
		expect(
			sentEmails.some(
				(mail) =>
					mail.to === own.email &&
					mail.subject.startsWith('Two-step verification was removed')
			)
		).toBe(true);
		expect(JSON.stringify([ownRead.body, olderRead.body])).not.toContain(
			'JBSWY3DPEHPK3PXP'
		);
	});
});
