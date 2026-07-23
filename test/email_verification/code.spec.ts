import { describe, it, expect, beforeAll, beforeEach } from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getUserStore,
	getBucketStore,
	getProjectStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import {
	sentEmails,
	resetSentEmails,
	lastEmail,
	extractCode
} from '../mail_capture.ts';

const CLIENT_ID = 'verify-code-app';
const PASSWORD = 'correct horse battery';

let bucketId: string;

async function startInteraction() {
	const auth = new AuthorizationRequest({
		client_id: CLIENT_ID,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie');
	return { uid, cookie };
}

// Register a fresh user and return the code-entry `ref` (from the redirect) plus the
// 6-digit code (from the captured email).
async function registerForCode(email: string) {
	const { uid, cookie } = await startInteraction();
	const { response } = await agent
		.ui({ uid })
		.registration.post(
			{ email, password: PASSWORD, confirmPassword: PASSWORD },
			{ headers: { cookie } }
		);
	expect(response.status).toBe(303);
	const location = getHeader(response, 'location');
	const ref = new URL(location, 'http://e.ly').searchParams.get('ref')!;
	const code = extractCode(lastEmail()!)!;
	return { ref, code };
}

describe('email verification — code method', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'code' });
		resetAdminMemoryStores();
		const bucket = await getBucketStore().create({
			name: 'Verify Code Bucket',
			emailVerificationRequired: true,
			verificationMethod: 'code'
		});
		bucketId = bucket._id;
		const project = await getProjectStore().create({
			name: 'Verify Code',
			slug: `verify-code-${Math.random()}`
		});
		await getProjectStore().update(project._id, {
			bucketId,
			clientIds: [CLIENT_ID]
		});
	});

	beforeEach(() => {
		resetSentEmails();
	});

	it('emails a 6-digit code and redirects to the code-entry page', async () => {
		const { ref, code } = await registerForCode('code-user@x.io');
		expect(ref).toBeTruthy();
		expect(code).toMatch(/^\d{6}$/);
		expect(sentEmails.length).toBe(1);
	});

	it('rejects a wrong code then accepts the correct one', async () => {
		const email = 'code-verify@x.io';
		const { ref, code } = await registerForCode(email);

		const wrong = await agent['verify-email'].code.post({
			ref,
			code: code === '000000' ? '111111' : '000000'
		});
		expect(wrong.response.status).toBe(200); // re-rendered code page, not verified
		expect((await getUserStore(bucketId).findByEmail(email))?.verified).toBe(
			false
		);

		const right = await agent['verify-email'].code.post({ ref, code });
		expect(right.response.status).toBe(200);
		expect((await getUserStore(bucketId).findByEmail(email))?.verified).toBe(
			true
		);
	});

	it('invalidates the code after too many wrong attempts', async () => {
		const email = 'code-cap@x.io';
		const { ref, code } = await registerForCode(email);
		const bad = code === '000000' ? '111111' : '000000';
		for (let i = 0; i < 5; i++) {
			await agent['verify-email'].code.post({ ref, code: bad });
		}
		// even the correct code is now refused; account stays unverified
		await agent['verify-email'].code.post({ ref, code });
		expect((await getUserStore(bucketId).findByEmail(email))?.verified).toBe(
			false
		);
	});

	it('enforces the resend cooldown (no second email)', async () => {
		const { ref } = await registerForCode('code-resend@x.io');
		resetSentEmails();
		const first = await agent['verify-email'].resend.post({ ref });
		expect(first.response.status).toBe(303); // new code issued
		expect(sentEmails.length).toBe(1);
		// the first resend supersedes the challenge; a second resend targets the fresh ref
		const newRef = new URL(
			getHeader(first.response, 'location'),
			'http://e.ly'
		).searchParams.get('ref')!;
		const second = await agent['verify-email'].resend.post({ ref: newRef });
		expect(second.response.status).toBe(429); // cooldown
		expect(sentEmails.length).toBe(1); // no additional email
	});
});
