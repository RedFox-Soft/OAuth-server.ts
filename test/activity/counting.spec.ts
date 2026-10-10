import { describe, it, expect, beforeAll, jest } from 'bun:test';

import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getActivityStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import { ADMIN_BUCKET_ID, DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { idpStub } from '../federation/idp_stub.ts';
import {
	provider,
	seedBucket as seedFederatedBucket,
	walk
} from '../federation/harness.ts';
import { present } from 'test/shape.ts';
import {
	Browser,
	PASSWORD,
	codeFor,
	figureOf,
	refresh,
	refreshTokenOf,
	seedBucket,
	seedUser,
	settled,
	signIn,
	signInAndRedeem,
	silentReauth,
	startCounting,
	thisMonth,
	today,
	uidOf,
	atDay
} from './fixtures.ts';

/*
 * The throttled case spends the door's failure cap, and every attempt costs an argon2 verification, so its
 * budget is the cap times a hash rather than bun's default (test/login_throttle/signin.spec.ts says the same).
 */
jest.setTimeout(30_000);

let shared: string;
let other: string;
let mfa: string;
let throttled: string;
let provisionedBucket: string;
let tv: string;

/* How much a period's figure moved across `action`. */
async function delta(
	bucketId: string,
	action: () => Promise<unknown>,
	period = thisMonth()
) {
	const before = await figureOf(bucketId, period);
	await action();
	const after = await figureOf(bucketId, period);
	return {
		total: after.total - before.total,
		local: after.byKind.local - before.byKind.local,
		federated: after.byKind.federated - before.byKind.federated,
		renewal: after.byKind.renewal - before.byKind.renewal,
		provisioned: after.provisioned - before.provisioned
	};
}

async function startInteraction(clientId: string) {
	const browser = new Browser();
	const started = await browser.authorize(
		new AuthorizationRequest({ client_id: clientId, scope: 'openid' })
	);
	return { browser, uid: uidOf(started.headers.get('location')) };
}

async function instanceTotal(): Promise<number> {
	await settled();
	let total = 0;
	for (const tally of (
		await getActivityStore().countPeriod(thisMonth(), new Date())
	).values()) {
		total += tally.total;
	}
	return total;
}

/**
 * @proves Every bucket — the default and administrators buckets included — counts each person it issued
 * tokens to once per month and once per day, under the kind of activity that issued them, and counts
 * nobody for a sign-in that issued nothing or a token issued to an application acting for itself.
 */
describe('active users counted per bucket', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'activity' });
		resetAdminMemoryStores();
		await ensureAdminSeed();
		await startCounting();
		shared = await seedBucket('Activity shared', ['act-app', 'act-app-2']);
		other = await seedBucket('Activity other', ['act-other']);
		mfa = await seedBucket('Activity MFA', ['act-mfa'], { totpRequired: true });
		throttled = await seedBucket('Activity throttle', ['act-throttle']);
		provisionedBucket = await seedBucket('Activity provisioned', [
			'act-provisioned'
		]);
		tv = await seedBucket('Activity TV', ['act-tv']);
	});

	it("counts an end user who signs in once in their bucket's month and day", async () => {
		const email = await seedUser(shared);

		const month = await delta(shared, () => signInAndRedeem('act-app', email));

		expect(month.total).toBe(1);
		expect(month.local).toBe(1);
		expect((await figureOf(shared, today())).total).toBeGreaterThanOrEqual(1);
	});

	it('leaves the count unchanged when an end user signs in again through another application of the bucket', async () => {
		const email = await seedUser(shared);
		await signInAndRedeem('act-app', email);

		const again = await delta(shared, () =>
			signInAndRedeem('act-app-2', email)
		);

		expect(again.total).toBe(0);
	});

	it('counts an end user of an application with no project in the default bucket', async () => {
		const email = await seedUser(DEFAULT_BUCKET_ID);

		const month = await delta(DEFAULT_BUCKET_ID, () =>
			signInAndRedeem('act-default', email)
		);

		expect(month.total).toBe(1);
	});

	it('counts an administrator signing in to the console in the administrators bucket, not the default one', async () => {
		const email = await seedUser(ADMIN_BUCKET_ID);
		const before = await figureOf(DEFAULT_BUCKET_ID, thisMonth());

		const month = await delta(ADMIN_BUCKET_ID, () =>
			signInAndRedeem('admin-panel', email)
		);

		expect(month.total).toBe(1);
		expect((await figureOf(DEFAULT_BUCKET_ID, thisMonth())).total).toBe(
			before.total
		);
	});

	it('counts a reused console session in the administrators bucket, not the default one', async () => {
		const email = await seedUser(ADMIN_BUCKET_ID);
		const browser = new Browser();
		await signInAndRedeem('admin-panel', email, { browser });
		const before = await figureOf(DEFAULT_BUCKET_ID, thisMonth());

		const reused = await delta(ADMIN_BUCKET_ID, () =>
			silentReauth(browser, 'admin-panel')
		);

		expect(reused.renewal).toBe(1);
		expect((await figureOf(DEFAULT_BUCKET_ID, thisMonth())).total).toBe(
			before.total
		);
	});

	it("leaves every other bucket's count unchanged when an end user of one bucket signs in", async () => {
		const email = await seedUser(shared);

		const elsewhere = await delta(other, () =>
			signInAndRedeem('act-app', email)
		);

		expect(elsewhere.total).toBe(0);
	});

	it('counts an end user who only refreshes tokens in a month as a renewal in that month', async () => {
		const email = await seedUser(shared);
		const restore = atDay('2031-03-15T12:00:00Z');
		let refreshToken: string;
		try {
			refreshToken = refreshTokenOf(
				await signInAndRedeem('act-app', email, { offline: true })
			);
		} finally {
			restore();
		}
		const later = atDay('2031-04-02T12:00:00Z');
		try {
			const april = await delta(
				shared,
				() => refresh('act-app', refreshToken),
				'2031-04'
			);

			expect(april).toMatchObject({ total: 1, local: 0, renewal: 1 });
		} finally {
			later();
		}
	});

	it('counts an end user signed in silently from an existing session as a renewal', async () => {
		const email = await seedUser(shared);
		const browser = new Browser();
		const restore = atDay('2031-05-20T12:00:00Z');
		try {
			await signInAndRedeem('act-app', email, { browser });
		} finally {
			restore();
		}
		const later = atDay('2031-06-03T12:00:00Z');
		try {
			const june = await delta(
				shared,
				() => silentReauth(browser, 'act-app'),
				'2031-06'
			);

			expect(june).toMatchObject({ total: 1, local: 0, renewal: 1 });
		} finally {
			later();
		}
	});

	it('counts an upstream sign-in under the upstream kind', async () => {
		const idp = await idpStub('https://idp-activity.test');
		const federated = await seedFederatedBucket('act-fed', {
			federation: [provider(idp.origin)]
		});
		const store = getUserStore(federated);
		const account = await store.create(
			'activity@acme.test',
			'irrelevant-hash',
			true
		);
		await store.update(account._id, {
			federated: [
				{
					providerId: 'acme-sso',
					sub: 'upstream-subject-1',
					linkedAt: new Date()
				}
			]
		});
		idp.expectDiscovery();
		const auth = new AuthorizationRequest({
			client_id: 'act-fed',
			scope: 'openid'
		});

		const month = await delta(federated, async () => {
			const { response } = await agent.auth.get({ query: auth.params });
			const cookie = present(
				response.headers.get('set-cookie'),
				'an interaction cookie'
			);
			const uid = getHeader(response, 'location').split('/')[2];
			const { complete } = await walk(uid, cookie, {
				idp,
				claims: { email: 'activity@acme.test' }
			});
			const code = new URL(
				present(complete?.location, 'a redirect'),
				'http://e.ly'
			).searchParams.get('code');
			await auth.getToken(present(code, 'an authorization code'));
		});

		expect(month).toMatchObject({ total: 1, federated: 1, local: 0 });
	});

	it('counts an end user approving a device-flow sign-in once the device receives its tokens', async () => {
		const email = await seedUser(tv);

		const month = await delta(tv, async () => {
			const started = await agent.device.auth.post({
				client_id: 'act-tv',
				scope: 'openid'
			});
			const { device_code, user_code } = started.data ?? {};
			if (!device_code || !user_code) throw new Error('expected a device code');
			const browser = new Browser();
			const page = await browser.request('/device');
			const xsrf = /name="xsrf" value="([0-9a-f]+)"/.exec(
				await page.text()
			)?.[1];
			const confirmed = await browser.post('/device', {
				xsrf: xsrf ?? '',
				user_code,
				confirm: 'yes'
			});
			const uid = uidOf(confirmed.headers.get('location'));
			const signedIn = await browser.post(`/ui/${uid}/login`, {
				username: email,
				password: PASSWORD
			});
			const consentUid = uidOf(signedIn.headers.get('location'));
			await browser.post(`/ui/${consentUid}/consent`, { action: 'allow' });
			const polled = await agent.token.post({
				client_id: 'act-tv',
				grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
				device_code
			});
			expect(polled.response.status).toBe(200);
		});

		expect(month).toMatchObject({ total: 1, local: 1 });
	});

	it('counts an account provisioned by a directory under the provisioned attribute', async () => {
		const email = await seedUser(provisionedBucket);
		const user = present(
			await getUserStore(provisionedBucket).findByEmail(email),
			'the user'
		);
		await getUserStore(provisionedBucket).update(user._id, {
			provisionedBy: 'activity-connection'
		});

		const month = await delta(provisionedBucket, () =>
			signInAndRedeem('act-provisioned', email)
		);

		expect(month).toMatchObject({ total: 1, provisioned: 1 });
	});

	it('counts nobody for a sign-in with a wrong password', async () => {
		const email = await seedUser(shared);
		const { browser, uid } = await startInteraction('act-app');

		const month = await delta(shared, () =>
			browser.post(`/ui/${uid}/login`, {
				username: email,
				password: 'not the password'
			})
		);

		expect(month.total).toBe(0);
	});

	it('counts nobody for a sign-in refused at the second factor', async () => {
		const email = await seedUser(mfa, { enrolled: true });
		const { browser, uid } = await startInteraction('act-mfa');
		await browser.post(`/ui/${uid}/login`, {
			username: email,
			password: PASSWORD
		});

		const month = await delta(mfa, () =>
			browser.post(`/ui/${uid}/totp`, {
				code: codeFor() === '000000' ? '111111' : '000000'
			})
		);

		expect(month.total).toBe(0);
	});

	it('counts nobody for a sign-in by a deactivated account', async () => {
		const email = await seedUser(shared);
		const user = present(
			await getUserStore(shared).findByEmail(email),
			'the user'
		);
		await getUserStore(shared).update(user._id, { active: false });
		const { browser, uid } = await startInteraction('act-app');

		const month = await delta(shared, () =>
			browser.post(`/ui/${uid}/login`, { username: email, password: PASSWORD })
		);

		expect(month.total).toBe(0);
	});

	it('counts nobody for a sign-in at a throttled door', async () => {
		const email = await seedUser(throttled);
		for (let i = 0; i < ApplicationConfig['loginThrottle.failureCap']; i += 1) {
			const { browser, uid } = await startInteraction('act-throttle');
			await browser.post(`/ui/${uid}/login`, {
				username: email,
				password: 'not the password'
			});
		}
		const { browser, uid } = await startInteraction('act-throttle');

		const month = await delta(throttled, () =>
			browser.post(`/ui/${uid}/login`, { username: email, password: PASSWORD })
		);

		expect(month.total).toBe(0);
	});

	it('counts nobody for a sign-in abandoned before its code is redeemed', async () => {
		const email = await seedUser(shared);
		const auth = new AuthorizationRequest({
			client_id: 'act-app',
			scope: 'openid'
		});

		const month = await delta(shared, () => signIn(new Browser(), auth, email));

		expect(month.total).toBe(0);
	});

	it('counts nobody for a token issued to an application acting for itself', async () => {
		const before = await instanceTotal();

		const res = await agent.token.post(
			{ grant_type: 'client_credentials' },
			{
				headers: AuthorizationRequest.basicAuthHeader(
					'act-service',
					'act-service-secret'
				)
			}
		);

		expect(res.response.status).toBe(200);
		expect(await instanceTotal()).toBe(before);
	});

	it('counts an end user once when their token requests arrive concurrently', async () => {
		const email = await seedUser(shared);
		const flows: { auth: AuthorizationRequest; code: string }[] = [];
		for (let i = 0; i < 5; i += 1) {
			const auth = new AuthorizationRequest({
				client_id: 'act-app',
				scope: 'openid'
			});
			flows.push({ auth, code: await signIn(new Browser(), auth, email) });
		}

		const month = await delta(shared, () =>
			Promise.all(flows.map(({ auth, code }) => auth.getToken(code)))
		);

		expect(month.total).toBe(1);
	});
});
