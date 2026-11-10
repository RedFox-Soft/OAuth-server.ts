import {
	afterAll,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';
import bootstrap, {
	bindClientToBucket,
	agent,
	getHeader
} from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getSmtpSettingsStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import type { SmtpSettings } from 'lib/adapters/types.ts';
import { elysia } from 'lib/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { clearEndUserAuthenticator } from 'lib/end_users/service.ts';
import { resetSentEmails, sentEmails } from 'lib/mail/mailer.ts';
import { present } from '../shape.ts';

const PASSWORD = 'correct horse battery';
const MAIL: SmtpSettings = {
	host: 'smtp.example.test',
	port: 587,
	secure: false,
	username: '',
	password: '',
	fromName: 'Acme',
	fromEmail: 'no-reply@example.test'
};
let bucketId: string;

async function signInWithPassword(email: string) {
	const auth = new AuthorizationRequest({
		client_id: 'totp-required-app',
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2] ?? '';
	const cookie = response.headers.get('set-cookie') ?? '';
	await elysia.handle(
		new Request(`http://e.ly/ui/${uid}/login`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie
			},
			body: new URLSearchParams({
				username: email,
				password: PASSWORD
			}).toString(),
			redirect: 'manual'
		})
	);
	return { uid, cookie };
}

async function open(url: string, cookie: string) {
	const res = await elysia.handle(
		new Request(new URL(url, 'http://e.ly'), {
			headers: { cookie },
			redirect: 'manual'
		})
	);
	return {
		status: res.status,
		text: await res.text(),
		location: res.headers.get('location')
	};
}

function linkTo(email: string): string {
	const mail = present(
		sentEmails.filter((m) => m.to === email).at(-1),
		'a mail to the person'
	);
	return present(
		mail.text.split(/\s+/).find((word) => word.includes('/totp/enroll/link')),
		'the link in the mail'
	);
}

/* A person in a project that requires a factor, whose factor an administrator just removed. */
async function removedByAdministrator(): Promise<{
	email: string;
	accountId: string;
}> {
	const email = `removed-${Math.random()}@x.io`;
	const user = await getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		true
	);
	await getUserStore(bucketId).update(user._id, {
		totp: { secret: 'JBSWY3DPEHPK3PXP', enrolledAt: new Date(), lastStep: 0 }
	});
	const bucket = present(await getBucketStore().find(bucketId), 'the bucket');
	await clearEndUserAuthenticator(bucket, user._id, async () => undefined);
	return { email, accountId: user._id };
}

/**
 * @proves After an administrator removed a person's authenticator, knowing the password is not enough to set up the
 * next one: the sign-in shows no secret until a link mailed to the person is opened in that same sign-in.
 */
describe('setting up a new factor after an administrator removed one', () => {
	let previousMail: SmtpSettings | null = null;

	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'totp' });
		resetAdminMemoryStores();
		previousMail = await getSmtpSettingsStore().get();
		await getSmtpSettingsStore().set(MAIL);
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Removal mark',
			totpRequired: true
		});
		bucketId = bucket._id;
		await bindClientToBucket('totp-required-app', bucketId);
	});

	afterAll(async () => {
		await getSmtpSettingsStore().set(
			previousMail ?? { ...MAIL, host: '', fromEmail: '' }
		);
	});

	beforeEach(() => {
		resetSentEmails();
	});

	it('shows no secret before the mailed link, and mails the link instead', async () => {
		const { email } = await removedByAdministrator();
		const { uid, cookie } = await signInWithPassword(email);

		const page = await open(`/ui/${uid}/totp/enroll`, cookie);

		expect(page.text).not.toContain('otpauth://');
		expect(linkTo(email)).toContain(`/ui/${uid}/totp/enroll/link`);
	});

	it('offers the secret once the link is opened in the same sign-in', async () => {
		const { email } = await removedByAdministrator();
		const { uid, cookie } = await signInWithPassword(email);
		await open(`/ui/${uid}/totp/enroll`, cookie);

		await open(linkTo(email), cookie);
		const page = await open(`/ui/${uid}/totp/enroll`, cookie);

		expect(page.text).toContain('otpauth://');
	});

	it('does nothing with the link in another sign-in', async () => {
		const { email } = await removedByAdministrator();
		const first = await signInWithPassword(email);
		await open(`/ui/${first.uid}/totp/enroll`, first.cookie);
		const link = linkTo(email);
		const other = await signInWithPassword(email);

		await open(link.replace(first.uid, other.uid), other.cookie);
		const page = await open(`/ui/${other.uid}/totp/enroll`, other.cookie);

		expect(page.text).not.toContain('otpauth://');
	});

	it('refuses a code posted before the link was opened', async () => {
		const { email, accountId } = await removedByAdministrator();
		const { uid, cookie } = await signInWithPassword(email);
		await open(`/ui/${uid}/totp/enroll`, cookie);

		await elysia.handle(
			new Request(`http://e.ly/ui/${uid}/totp/enroll`, {
				method: 'POST',
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
					cookie
				},
				body: new URLSearchParams({ code: '123456' }).toString(),
				redirect: 'manual'
			})
		);

		expect(
			(await getUserStore(bucketId).find(accountId))?.totp
		).toBeUndefined();
	});
});
