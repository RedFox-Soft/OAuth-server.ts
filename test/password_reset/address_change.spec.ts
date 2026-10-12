import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, { agent } from '../test_helper.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { updateEndUser } from 'lib/end_users/service.ts';
import { request } from 'lib/password_reset/challenge.ts';
import { emailsTo, extractResetUrl, resetSentEmails } from '../mail_capture.ts';
import { present } from 'test/shape.js';

const OLD_PASSWORD = 'correct horse battery';
const NEW_PASSWORD = 'staple correct horse';

let bucket: UserBucket;

function tokenMailedTo(address: string): string {
	const url = present(
		extractResetUrl(present(emailsTo(address).at(-1), 'a reset message')),
		'a reset link'
	);
	return present(new URL(url).searchParams.get('token'), 'a token');
}

/* A reset link requested at the old address, and then an administrator moving the account to a new one. */
async function linkMailedBeforeTheMove(old: string, moved: string) {
	const user = await getUserStore(bucket._id).create(
		old,
		await Bun.password.hash(OLD_PASSWORD),
		true
	);
	await request(old, bucket._id);
	const token = tokenMailedTo(old);
	await updateEndUser(
		bucket,
		{ kind: 'admin' },
		user._id,
		{ email: moved },
		async () => {}
	);
	return { user, token };
}

/* A refusal's page lands in `error.value`; Eden has already read the body. */
function pageOf(result: { error?: { value?: unknown } | null }): string {
	const value = result.error?.value;
	return typeof value === 'string' ? value : JSON.stringify(value);
}

beforeAll(async () => {
	await bootstrap(import.meta.url, { config: 'reset' });
	const created = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: 'Moved Address Bucket'
	});
	bucket = present(await getBucketStore().find(created._id), 'the bucket');
});

/**
 * @proves A password-reset link proves only the mailbox it reached: once an administrator changes the
 * account's address, a link sent to the old one neither sets a password nor verifies the new address.
 */
describe('a reset link mailed before the address changed', () => {
	beforeEach(() => {
		resetSentEmails();
	});

	it('renders the page an unknown link renders', async () => {
		const { token } = await linkMailedBeforeTheMove(
			'moved-get@x.io',
			'moved-get-new@x.io'
		);

		const opened = await agent['reset-password'].get({ query: { token } });
		const unknown = await agent['reset-password'].get({
			query: { token: 'no-such-token-was-ever-issued' }
		});

		expect(opened.response.status).toBe(400);
		expect(pageOf(opened)).toBe(pageOf(unknown));
	});

	it('sets no password and verifies nothing when submitted', async () => {
		const { user, token } = await linkMailedBeforeTheMove(
			'moved-post@x.io',
			'moved-post-new@x.io'
		);

		const submitted = await agent['reset-password'].post({
			token,
			password: NEW_PASSWORD,
			confirmPassword: NEW_PASSWORD
		});

		expect(submitted.response.status).toBe(400);
		const after = present(
			await getUserStore(bucket._id).find(user._id),
			'the account'
		);
		expect(await Bun.password.verify(OLD_PASSWORD, after.password)).toBeTrue();
		expect(after.verified).toBeFalse();
	});
});
