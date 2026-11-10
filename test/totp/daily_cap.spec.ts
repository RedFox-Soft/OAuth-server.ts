import {
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap, {
	bindClientToBucket,
	agent,
	getHeader
} from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { encodeBase32, decodeBase32 } from 'lib/totp/base32.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import {
	ACCOUNT_FAILURE_CAP,
	DAILY_FAILURE_CAP,
	MAX_ATTEMPTS_PER_INTERACTION
} from 'lib/totp/consts.ts';
import { verifyForAccount } from 'lib/totp/verify.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { resetSentEmails, sentEmails } from 'lib/mail/mailer.ts';

const SECRET = encodeBase32(Buffer.from('12345678901234567890', 'ascii'));
const PASSWORD = 'correct horse battery';
let bucketId: string;

const right = () => hotp(decodeBase32(SECRET), stepFor(epochTime()));
const wrongCode = () => (right() === '000000' ? '111111' : '000000');

async function enrolledPerson(): Promise<{ accountId: string; email: string }> {
	const email = `daily-${Math.random()}@x.io`;
	const user = await getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		true
	);
	await getUserStore(bucketId).update(user._id, {
		totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0, via: 'self' }
	});
	return { accountId: user._id, email };
}

function later(minutes: number) {
	setSystemTime(new Date(Date.now() + minutes * 60 * 1000));
}

/* A password sign-in through the optional project's client, then `codes` wrong codes at its code step. */
async function wrongCodesAfterPassword(email: string, codes: number) {
	const auth = new AuthorizationRequest({
		client_id: 'totp-optional-app',
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2] ?? '';
	const cookie = response.headers.get('set-cookie') ?? '';
	const post = (path: string, fields: Record<string, string>) =>
		elysia.handle(
			new Request(`http://e.ly/ui/${uid}/${path}`, {
				method: 'POST',
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
					cookie
				},
				body: new URLSearchParams(fields).toString(),
				redirect: 'manual'
			})
		);
	await post('login', { username: email, password: PASSWORD });
	for (let i = 0; i < codes; i++) await post('totp', { code: wrongCode() });
}

/**
 * @proves Someone who knows a person's password cannot guess the code from their authenticator app at more than thirty
 * tries a day, and the person is told, once a day, that their password is known.
 */
describe('guessing the code behind a known password', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'totp' });
		resetAdminMemoryStores();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Daily cap'
		});
		bucketId = bucket._id;
		await bindClientToBucket('totp-optional-app', bucketId);
	});

	afterEach(() => {
		setSystemTime();
		resetSentEmails();
	});

	it('refuses even the right code once thirty wrong ones were tried in a day', async () => {
		const { accountId } = await enrolledPerson();
		const windows = DAILY_FAILURE_CAP / ACCOUNT_FAILURE_CAP;
		for (let w = 0; w < windows; w++) {
			for (let i = 0; i < ACCOUNT_FAILURE_CAP; i++) {
				await verifyForAccount(bucketId, accountId, wrongCode());
			}
			later(16);
		}

		expect(await verifyForAccount(bucketId, accountId, right())).toEqual({
			ok: false,
			reason: 'throttled'
		});
	});

	it('accepts the right code again once the day has passed', async () => {
		const { accountId } = await enrolledPerson();
		for (let w = 0; w < DAILY_FAILURE_CAP / ACCOUNT_FAILURE_CAP; w++) {
			for (let i = 0; i < ACCOUNT_FAILURE_CAP; i++) {
				await verifyForAccount(bucketId, accountId, wrongCode());
			}
			later(16);
		}
		later(24 * 60);

		expect(await verifyForAccount(bucketId, accountId, right())).toEqual({
			ok: true
		});
	});

	it('mails the person once a day when someone with the password runs out of guesses', async () => {
		const { email } = await enrolledPerson();
		const perInteraction = MAX_ATTEMPTS_PER_INTERACTION;
		const warnings = () =>
			sentEmails.filter(
				(mail) =>
					mail.to === email && mail.subject.includes('signed in with your')
			);

		for (let i = 0; i < ACCOUNT_FAILURE_CAP / perInteraction; i++) {
			await wrongCodesAfterPassword(email, perInteraction);
		}
		expect(warnings()).toHaveLength(1);

		later(16);
		for (let i = 0; i < ACCOUNT_FAILURE_CAP / perInteraction; i++) {
			await wrongCodesAfterPassword(email, perInteraction);
		}
		expect(warnings()).toHaveLength(1);
	});
});
