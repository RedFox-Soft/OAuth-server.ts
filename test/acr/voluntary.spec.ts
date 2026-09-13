import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getProjectStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { decode as decodeJWT } from 'lib/helpers/jwt.ts';
import { idTokenOf, refreshTokenOf } from './response.ts';
import { encodeBase32, decodeBase32 } from 'lib/totp/base32.ts';
import { hotp, stepFor } from 'lib/totp/code.ts';
import epochTime from 'lib/helpers/epoch_time.ts';

const PASSWORD = 'correct horse battery';
const SECRET = encodeBase32(Buffer.from('12345678901234567890', 'ascii'));
const PWD = 'urn:example:acr:pwd';
const MFA = 'urn:example:acr:mfa';

let plainBucketId: string;
let mfaBucketId: string;
let defaultsBucketId: string;

async function seedBucket(
	name: string,
	clientId: string,
	fields: Record<string, unknown> = {}
): Promise<string> {
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		...fields
	});
	const project = await getProjectStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name,
		slug: `${clientId}-${Math.random()}`
	});
	await getProjectStore().update(project._id, {
		bucketId: bucket._id,
		clientIds: [clientId]
	});
	return bucket._id;
}

async function seedUser(bucketId: string, email: string, enrolled = false) {
	const user = await getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		[],
		true
	);
	if (enrolled) {
		await getUserStore(bucketId).update(user._id, {
			totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0 }
		});
	}
	return user;
}

async function postForm(
	path: string,
	cookie: string,
	fields: Record<string, string>
) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
			body: new URLSearchParams(fields).toString(),
			redirect: 'manual'
		})
	);
	return { status: res.status, location: res.headers.get('location') };
}

async function startInteraction(auth: AuthorizationRequest) {
	const { response } = await agent.auth.get({ query: auth.params });
	const location = getHeader(response, 'location');
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid: location.split('/')[2], cookie };
}

/* Sign in and return the code the client receives. */
async function codeFrom(
	auth: AuthorizationRequest,
	email: string,
	{ second = false } = {}
) {
	const { uid, cookie } = await startInteraction(auth);
	let res = await postForm(`/ui/${uid}/login`, cookie, {
		username: email,
		password: PASSWORD
	});
	if (second) {
		res = await postForm(`/ui/${uid}/totp`, cookie, {
			code: hotp(decodeBase32(SECRET), stepFor(epochTime()))
		});
	}
	expect(res.location ?? '').toContain('/callback');
	return new URL(res.location as string).searchParams.get('code') as string;
}

function preferring(values: string, clientId = 'acr-app') {
	return new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid',
		acr_values: values
	});
}

/**
 * @proves A relying party that asks how the end user authenticated is told the context the sign-in
 * actually satisfied, a preference that cannot be met never fails the request, and a request that
 * asks nothing is answered exactly as before.
 */
describe('a preferred authentication context', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'acr' });
		resetAdminMemoryStores();
		plainBucketId = await seedBucket('ACR plain', 'acr-app');
		mfaBucketId = await seedBucket('ACR mfa', 'acr-mfa-app', {
			totpRequired: true
		});
		defaultsBucketId = await seedBucket('ACR defaults', 'acr-defaults-app');
	});

	it('carries the context the sign-in satisfied when the request names preferences', async () => {
		const email = `pref-${Math.random()}@x.io`;
		await seedUser(plainBucketId, email);
		const auth = preferring(PWD);

		const token = await auth.getToken(await codeFrom(auth, email));

		expect(decodeJWT(idTokenOf(token)).payload.acr).toBe(PWD);
	});

	it('completes the request and reports the context actually satisfied when no preference can be met', async () => {
		const email = `unmet-pref-${Math.random()}@x.io`;
		await seedUser(plainBucketId, email);
		// Asks for the multi-factor context from a bucket that never demands a second factor.
		const auth = preferring(MFA);

		const token = await auth.getToken(await codeFrom(auth, email));

		expect(token.response.status).toBe(200);
		expect(decodeJWT(idTokenOf(token)).payload.acr).toBe(PWD);
	});

	it('reports a different context for a sign-in that presented a second factor', async () => {
		const email = `mfa-${Math.random()}@x.io`;
		await seedUser(mfaBucketId, email, true);
		const auth = preferring(`${PWD} ${MFA}`, 'acr-mfa-app');

		const token = await auth.getToken(
			await codeFrom(auth, email, { second: true })
		);

		expect(decodeJWT(idTokenOf(token)).payload.acr).toBe(MFA);
	});

	it('carries no authentication context when the request asks for none', async () => {
		const email = `silent-${Math.random()}@x.io`;
		await seedUser(plainBucketId, email);
		const auth = new AuthorizationRequest({
			client_id: 'acr-app',
			scope: 'openid'
		});

		const token = await auth.getToken(await codeFrom(auth, email));

		// The regression guard for every existing deployment: unasked, the claim stays absent.
		expect(decodeJWT(idTokenOf(token)).payload).not.toHaveProperty('acr');
	});

	it('reports the original sign-in context when the client refreshes its tokens', async () => {
		const email = `refresh-${Math.random()}@x.io`;
		await seedUser(plainBucketId, email);
		const auth = new AuthorizationRequest({
			client_id: 'acr-app',
			scope: 'openid offline_access',
			prompt: 'consent',
			acr_values: PWD
		});

		const first = await auth.getToken(await codeFrom(auth, email));
		expect(refreshTokenOf(first)).toBeTruthy();

		const refreshed = await agent.token.post({
			client_id: 'acr-app',
			grant_type: 'refresh_token',
			refresh_token: refreshTokenOf(first)
		});

		expect(refreshed.response.status).toBe(200);
		// Still describes the sign-in that happened; never silently upgraded.
		expect(decodeJWT(idTokenOf(refreshed)).payload.acr).toBe(PWD);
	});

	it('applies the contexts a client registered when the request names none', async () => {
		const email = `defaults-${Math.random()}@x.io`;
		await seedUser(defaultsBucketId, email);
		const auth = new AuthorizationRequest({
			client_id: 'acr-defaults-app',
			scope: 'openid'
		});

		const token = await auth.getToken(await codeFrom(auth, email));

		// The request named no context; the client's registered defaults put the claim in the mask.
		expect(decodeJWT(idTokenOf(token)).payload.acr).toBe(PWD);
	});

	it('honours a context the request names itself over the ones the client registered', async () => {
		const email = `override-${Math.random()}@x.io`;
		await seedUser(defaultsBucketId, email);
		// The client registered the multi-factor context; this request requires the password one,
		// which its sign-in does satisfy. The registration specification has the request win.
		const auth = new AuthorizationRequest({
			client_id: 'acr-defaults-app',
			scope: 'openid',
			claims: { id_token: { acr: { essential: true, values: [PWD] } } }
		});

		const token = await auth.getToken(await codeFrom(auth, email));

		expect(token.response.status).toBe(200);
		expect(decodeJWT(idTokenOf(token)).payload.acr).toBe(PWD);
	});
});
