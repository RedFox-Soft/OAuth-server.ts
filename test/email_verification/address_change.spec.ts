import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';

import bootstrap, { agent } from '../test_helper.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import type { UserBucket, VerificationMethod } from 'lib/adapters/types.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { updateEndUser } from 'lib/end_users/service.ts';
import { issueAndSend } from 'lib/verification/challenge.ts';
import {
	emailsTo,
	extractCode,
	extractVerifyUrl,
	resetSentEmails
} from '../mail_capture.ts';
import { present } from 'test/shape.js';

async function bucketVerifyingBy(
	method: VerificationMethod
): Promise<UserBucket> {
	const created = await getBucketStore().create({
		name: `addr-${Math.random()}`,
		ownerGroupId: UNASSIGNED_GROUP_ID
	});
	return present(
		await getBucketStore().update(created._id, { verificationMethod: method }),
		'the bucket'
	);
}

function tokenMailedTo(address: string): string {
	const url = present(
		extractVerifyUrl(present(emailsTo(address).at(-1), 'a message')),
		'a link'
	);
	return present(new URL(url).searchParams.get('token'), 'a token');
}

/* An administrator — or a directory — moving the account to another address, as the console's change does. */
async function moveTo(bucket: UserBucket, id: string, email: string) {
	await updateEndUser(bucket, { kind: 'admin' }, id, { email }, async () => {});
}

/**
 * @proves A verification message proves only the address it reached: once an account's address changes, a
 * link or code sent to the old address verifies nothing, while a message to the current address still does.
 */
describe('verifying an address that has since changed', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'link' });
	});

	beforeEach(() => {
		resetSentEmails();
	});

	it('refuses a link sent to the old address, as it refuses an unknown one', async () => {
		const bucket = await bucketVerifyingBy('link');
		const user = await getUserStore(bucket._id).create(
			'old-link@example.com',
			'h',
			false
		);
		await issueAndSend(user, bucket);
		const token = tokenMailedTo('old-link@example.com');
		await moveTo(bucket, user._id, 'new-link@example.com');

		const opened = await agent['verify-email'].get({ query: { token } });
		const unknown = await agent['verify-email'].get({
			query: { token: 'not-a-real-token' }
		});

		expect(opened.response.status).toBe(unknown.response.status);
		expect((await getUserStore(bucket._id).find(user._id))?.verified).toBe(
			false
		);
	});

	it('refuses a code sent to the old address', async () => {
		const bucket = await bucketVerifyingBy('code');
		const user = await getUserStore(bucket._id).create(
			'old-code@example.com',
			'h',
			false
		);
		const { id: ref } = await issueAndSend(user, bucket);
		const code = present(
			extractCode(
				present(emailsTo('old-code@example.com').at(-1), 'a message')
			),
			'a code'
		);
		await moveTo(bucket, user._id, 'new-code@example.com');

		await agent['verify-email'].code.post({ ref, code });

		expect((await getUserStore(bucket._id).find(user._id))?.verified).toBe(
			false
		);
	});

	it('verifies the current address with a link sent to it', async () => {
		const bucket = await bucketVerifyingBy('link');
		const user = await getUserStore(bucket._id).create(
			'before@example.com',
			'h',
			false
		);
		await moveTo(bucket, user._id, 'current@example.com');
		const moved = present(
			await getUserStore(bucket._id).find(user._id),
			'the account'
		);
		await issueAndSend(moved, bucket);

		const opened = await agent['verify-email'].get({
			query: { token: tokenMailedTo('current@example.com') }
		});

		expect(opened.response.status).toBe(200);
		expect((await getUserStore(bucket._id).find(user._id))?.verified).toBe(
			true
		);
	});
});
