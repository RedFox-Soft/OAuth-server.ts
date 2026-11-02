import {
	afterAll,
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	mock,
	spyOn
} from 'bun:test';

import bootstrap, { type Setup } from '../test_helper.js';
import { assertNoPendingInterceptors } from '../fetch_mock.js';
import {
	getConnectedAccountStore,
	getSmtpSettingsStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { SmtpSettings } from 'lib/adapters/types.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import {
	destroyBucketAccounts,
	destroyConnectedAccountsOf,
	disconnect
} from 'lib/connected_services/accounts.ts';
import { mailsSettled } from 'lib/connected_services/mail.ts';
import epochTime from 'lib/helpers/epoch_time.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import { resetSentEmails, sentEmails } from 'lib/mail/mailer.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present } from '../shape.js';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { createAdministrator } from '../administrators.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import { admin } from '../connected_services/harness.ts';
import { githubStub, unique } from '../connected_services/stubs.ts';
import {
	allowAccount,
	connected,
	exchange,
	githubService,
	project,
	refused,
	signIn
} from './harness.ts';

const MAIL: SmtpSettings = {
	host: 'smtp.example.test',
	port: 587,
	secure: false,
	username: '',
	password: '',
	fromName: 'FoxAuth',
	fromEmail: 'auth@example.test'
};
const NO_MAIL: SmtpSettings = { ...MAIL, host: '', fromEmail: '' };

/**
 * @proves The person is told by mail, once, when a connected account breaks, and when an administrator or a
 * service's deletion removes it; never for their own disconnect or a deletion of the person or project, never at an
 * address nobody proved, and never with a token or an identifier in it.
 */
describe('mail about a person’s connected accounts', () => {
	let setup: Setup;
	let cookie: string;

	beforeAll(async () => {
		setup = await bootstrap(import.meta.url, { config: 'upstream_tokens' });
		cookie = await cookieFor(await createAdministrator('super'));
	});

	beforeEach(async () => {
		resetKeyringForTests(TEST_KEYRING);
		spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(false);
		await getSmtpSettingsStore().set(MAIL);
		resetSentEmails();
	});

	afterEach(() => {
		assertNoPendingInterceptors();
		mock.restore();
	});

	afterAll(async () => {
		await getSmtpSettingsStore().set(NO_MAIL);
	});

	/* A person with a proven address and one GitHub account an agent may use. */
	async function person(
		fields: Parameters<typeof connected>[2] = {},
		verified = true
	) {
		const accountId = unique('person');
		const email = `${accountId}@people.example`;
		const service = await githubService();
		const record = await connected(accountId, service, fields);
		const signedIn = await signIn(setup, 'agent', accountId);
		await getUserStore(DEFAULT_BUCKET_ID).update(accountId, {
			email,
			verified
		});
		await allowAccount(signedIn.grantId, record);
		return { accountId, email, service, record, signedIn };
	}

	const to = (email: string) =>
		sentEmails.filter((message) => message.to === email);

	it('mails once when an account breaks, and not again while it stays broken', async () => {
		const { email, service, record, signedIn } = await person({
			accessTokenExpiresAt: epochTime() - 10
		});
		githubStub().expectRefreshRejected();

		refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);
		refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);
		await mailsSettled();

		const mails = to(email);
		expect(mails).toHaveLength(1);
		expect(mails[0].subject).toContain('Reconnect');
		const text = JSON.stringify(mails[0]);
		for (const secret of [
			present(record.accessToken, 'a token'),
			present(record.refreshToken, 'a refresh token'),
			record._id,
			DEFAULT_BUCKET_ID
		]) {
			expect(text).not.toContain(secret);
		}
	});

	it('mails again after a reconnect breaks once more', async () => {
		const { email, service, record, signedIn } = await person({
			accessTokenExpiresAt: epochTime() - 10
		});
		githubStub().expectRefreshRejected();
		refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);
		const { broken: _broken, ...reconnected } = present(
			await getConnectedAccountStore().find(DEFAULT_BUCKET_ID, record._id),
			'the account'
		);
		await getConnectedAccountStore().put({
			...reconnected,
			accessToken: unique('fresh'),
			refreshToken: unique('fresh-refresh')
		});
		githubStub().expectRefreshRejected();

		refused(
			await exchange({
				subjectToken: signedIn.accessToken,
				audience: service.id
			})
		);
		await mailsSettled();

		expect(to(email)).toHaveLength(2);
	});

	it('mails the person when an administrator disconnects the account', async () => {
		const { accountId, email, record } = await person();

		await admin(
			cookie,
			'DELETE',
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/users/${accountId}/connected-accounts/${encodeURIComponent(record._id)}`
		);
		await mailsSettled();

		const mails = to(email);
		expect(mails).toHaveLength(1);
		expect(mails[0].subject).toStartWith(
			'Your GitHub account was disconnected from'
		);
	});

	it('mails the people at a service an administrator deletes', async () => {
		const first = await person();
		await connected(unique('person'), first.service);

		const answer = await admin(
			cookie,
			'DELETE',
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/connected-services/${first.service.id}`
		);
		await mailsSettled();

		expect(answer.status).toBe(200);
		expect(to(first.email)).toHaveLength(1);
	});

	it('sends nothing for the person’s own disconnect, or a deletion of the person or the project', async () => {
		const own = await person();
		const deleted = await person();
		const destroyed = await person();

		await disconnect({
			bucket: await project(),
			accountId: own.accountId,
			connectedAccountId: own.record._id,
			by: 'person'
		});
		await destroyConnectedAccountsOf(await project(), deleted.accountId);
		await destroyBucketAccounts(await project());
		await mailsSettled();

		expect(to(own.email)).toHaveLength(0);
		expect(to(deleted.email)).toHaveLength(0);
		expect(to(destroyed.email)).toHaveLength(0);
	});

	it('sends nothing to an address nobody proved, or with no mail configured, and fails nothing', async () => {
		const unproven = await person(
			{ accessTokenExpiresAt: epochTime() - 10 },
			false
		);
		githubStub().expectRefreshRejected();
		refused(
			await exchange({
				subjectToken: unproven.signedIn.accessToken,
				audience: unproven.service.id
			})
		);
		await getSmtpSettingsStore().set(NO_MAIL);
		const unconfigured = await person();

		const answer = await admin(
			cookie,
			'DELETE',
			`/admin/api/projects/${DEFAULT_BUCKET_ID}/users/${unconfigured.accountId}/connected-accounts/${encodeURIComponent(unconfigured.record._id)}`
		);
		await mailsSettled();

		expect(answer.status).toBe(200);
		expect(to(unproven.email)).toHaveLength(0);
		expect(to(unconfigured.email)).toHaveLength(0);
	});
});
