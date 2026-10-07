import { describe, it, expect, beforeAll, jest } from 'bun:test';

import bootstrap, {
	agent,
	getHeader,
	SESSION_COOKIE_PREFIX
} from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getProjectStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import nanoid from 'lib/helpers/nanoid.ts';

/*
 * Each case spends an argon2 verification or two, which puts a case near bun's 5s default under the
 * contention of a full run; the budget is the cost of the hash, not a property of the contract.
 */
jest.setTimeout(30_000);

const PASSWORD = 'correct horse battery';

/* A browser that knows the interaction's address and nothing else: its cookie is one it made up. */
const FOREIGN_COOKIE = '_interaction=chosen-by-the-holder-of-the-uid';

let passwordBucketId: string;
let secondFactorBucketId: string;

async function seedBucket(
	name: string,
	clientId: string,
	fields: Record<string, unknown>
): Promise<string> {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		...fields
	});
	const project = await getProjectStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		slug: `${clientId}-${nanoid()}`
	});
	await getProjectStore().update(project._id, {
		bucketId: bucket._id,
		clientIds: [clientId]
	});
	return bucket._id;
}

async function seedUser(bucketId: string): Promise<string> {
	const email = `${nanoid()}@x.io`;
	await getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		true
	);
	return email;
}

/* The end user's browser, sent to /auth by the relying party. */
async function startInteraction(clientId: string) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2];
	const setCookie = response.headers.get('set-cookie');
	if (!setCookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie: setCookie.split(';')[0] };
}

async function send(
	path: string,
	cookie: string,
	fields?: Record<string, string>
) {
	const headers: Record<string, string> = { cookie };
	if (fields) headers['content-type'] = 'application/x-www-form-urlencoded';
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method: fields ? 'POST' : 'GET',
			headers,
			body: fields ? new URLSearchParams(fields).toString() : undefined,
			redirect: 'manual'
		})
	);
	return {
		status: res.status,
		text: await res.text(),
		setCookie: res.headers.getSetCookie()
	};
}

/**
 * @proves A sign-in continues only in the browser it began in: a browser holding just the interaction's
 * address can neither sign in through it nor read the second factor being enrolled, and cannot tell a
 * live address from an unknown one.
 */
describe('a sign-in reached from another browser', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		passwordBucketId = await seedBucket(
			'Binding Password',
			'binding-password-app',
			{}
		);
		secondFactorBucketId = await seedBucket(
			'Binding Second Factor',
			'binding-second-factor-app',
			{ totpRequired: true }
		);
	});

	it('refuses the sign-in screen to a browser whose interaction cookie was not issued for it', async () => {
		const { uid } = await startInteraction('binding-password-app');

		const page = await send(`/ui/${uid}/login`, FOREIGN_COOKIE);

		expect(page.status).toBe(400);
		expect(page.text).not.toContain('name="password"');
	});

	it('issues no session for correct credentials submitted from another browser', async () => {
		const email = await seedUser(passwordBucketId);
		const { uid } = await startInteraction('binding-password-app');

		const login = await send(`/ui/${uid}/login`, FOREIGN_COOKIE, {
			username: email,
			password: PASSWORD
		});

		expect(login.status).toBe(400);
		expect(
			login.setCookie.filter((c) => c.startsWith(SESSION_COOKIE_PREFIX))
		).toEqual([]);
	});

	it('does not show the authenticator secret to another browser after the end user entered their password', async () => {
		const email = await seedUser(secondFactorBucketId);
		const { uid, cookie } = await startInteraction('binding-second-factor-app');
		const password = await send(`/ui/${uid}/login`, cookie, {
			username: email,
			password: PASSWORD
		});
		expect(password.status).toBe(303);

		const enrol = await send(`/ui/${uid}/totp/enroll`, FOREIGN_COOKIE);

		expect(enrol.status).toBe(400);
		expect(enrol.text).not.toContain('otpauth://');
	});

	it('leaves the sign-in usable in its own browser after another browser was refused', async () => {
		const { uid, cookie } = await startInteraction('binding-password-app');
		await send(`/ui/${uid}/login`, FOREIGN_COOKIE);

		const page = await send(`/ui/${uid}/login`, cookie);

		expect(page.status).toBe(200);
		expect(page.text).toContain(uid);
	});

	it('answers a live address with a foreign cookie exactly as it answers an unknown address', async () => {
		const { uid } = await startInteraction('binding-password-app');
		const unknown = nanoid();

		const live = await send(`/ui/${uid}/login`, FOREIGN_COOKIE);
		const missing = await send(`/ui/${unknown}/login`, FOREIGN_COOKIE);

		expect(live.status).toBe(missing.status);
		expect(live.text.replaceAll(uid, '<uid>')).toBe(
			missing.text.replaceAll(unknown, '<uid>')
		);
	});
});
