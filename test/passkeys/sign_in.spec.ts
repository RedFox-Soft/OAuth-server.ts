import {
	afterEach,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap, {
	bindClientToBucket,
	encodeParams,
	findSessionSetCookie
} from '../test_helper.js';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { setPeerResolverForTests } from 'lib/helpers/caller_address.ts';
import { elysia } from 'lib/index.ts';
import { countPasskeyFailure } from 'lib/passkeys/limits.ts';
import { present, shaped } from '../shape.ts';
import { shownAccount } from '../consent_form.js';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	BETA,
	Browser,
	SUB,
	acceptPasskeys,
	claimsOf,
	codeAfter,
	holdingPasskey,
	mailOn,
	postCredential,
	postPasskey,
	project,
	redeem,
	signInPage,
	signInWithPasskey,
	textOf,
	type Project
} from './helpers.ts';

let acme: Project;

const MULTI_FACTOR = 'urn:example:acr:mfa';

/* A device holding a passkey for this instance's host that no project here has a record of. */
async function stranger(): Promise<SoftAuthenticator> {
	const device = new SoftAuthenticator();
	await device.create(
		{ challenge: 'AAAA', rp: { id: 'e.ly' }, user: { id: 'c29tZW9uZQ' } },
		{ origin: 'http://e.ly' }
	);
	return device;
}

/* Every request from now on comes from `address`, as a browser's connection would. */
function from(address: string): void {
	setPeerResolverForTests(() => address);
}

/*
 * Failed passkey attempts already counted against `address` this hour. The clock is first set ten minutes into an
 * hour: the bound is per UTC hour, so a case that moved the clock across the hour's end would start a new count.
 */
async function failuresFrom(address: string, count: number): Promise<void> {
	const now = new Date();
	now.setUTCMinutes(10, 0, 0);
	setSystemTime(now);
	from(address);
	for (let i = 0; i < count; i++) {
		await countPasskeyFailure(new Request('http://e.ly/'));
	}
}

/* One refused attempt from the current address: a passkey nobody here holds, answering a fresh page. */
async function refusedAttempt(): Promise<Response> {
	const browser = new Browser(acme.origin);
	const page = await signInPage(browser, acme);
	return postPasskey(browser, await stranger(), acme, page);
}

/**
 * @proves A person signs in to an app with a passkey alone: the app learns of a multi-factor sign-in with the
 * passkey's own methods, no code is ever asked, "Remember me" decides how long the session lasts as after a password,
 * and a device is approved the same way. The door judges each challenge once, and an address that keeps failing is
 * refused before anything is looked up, while a success never counts against it.
 */
describe('signing in with a passkey', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		acme = await project(ACME);
		await getBucketStore().update(acme.bucketId, { displayName: 'Acme' });
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
	});

	afterEach(() => {
		setSystemTime();
		setPeerResolverForTests(null);
	});

	it('reaches the app with the multi-factor context and the passkey’s methods', async () => {
		const { device } = await holdingPasskey(acme);

		const { auth, code } = await signInWithPasskey(
			new Browser(acme.origin),
			device,
			acme
		);

		const claims = claimsOf((await redeem(acme, auth, code)).id_token);
		expect({
			acr: claims.acr,
			amr: Array.isArray(claims.amr)
				? claims.amr.map(String).sort()
				: claims.amr
		}).toEqual({ acr: MULTI_FACTOR, amr: ['mfa', 'pop', 'user'] });
	});

	it('asks no code in a project that requires one, from someone without an authenticator app', async () => {
		const beta = await project(BETA, { settings: { totpRequired: true } });
		const { device } = await holdingPasskey(beta);
		const browser = new Browser(beta.origin);
		const page = await signInPage(browser, beta);

		const posted = await postPasskey(browser, device, beta, page);

		expect(posted.headers.get('location') ?? '').not.toMatch(/\/totp/);
		expect(await codeAfter(browser, posted, page.url)).toBeString();
	});

	it('asks no code from someone who holds an authenticator app', async () => {
		const { device } = await holdingPasskey(acme, { keepCode: true });
		const browser = new Browser(acme.origin);
		const page = await signInPage(browser, acme);

		const posted = await postPasskey(browser, device, acme, page);

		expect(posted.headers.get('location') ?? '').not.toMatch(/\/totp/);
		expect(await codeAfter(browser, posted, page.url)).toBeString();
	});

	it('ends the session with the browser when "Remember me" is unticked', async () => {
		const { device } = await holdingPasskey(acme);
		const browser = new Browser(acme.origin);
		const page = await signInPage(browser, acme);

		const posted = await postPasskey(browser, device, acme, page, {
			ticked: false
		});

		const written = present(
			findSessionSetCookie(posted.headers.getSetCookie()),
			'the session cookie'
		);
		expect(written).not.toMatch(/;\s*Expires=/i);
		expect(written).not.toMatch(/;\s*Max-Age=/i);
	});

	it('remembers the sign-in on a page without a "Remember me" checkbox', async () => {
		const gamma = await project({ slug: 'gamma', clientId: SUB.clientId });
		const { device } = await holdingPasskey(gamma);
		await acceptPasskeys(gamma.bucketId, true, { passwordLogin: false });
		const browser = new Browser(gamma.origin);
		const page = await signInPage(browser, gamma);

		const posted = await postPasskey(browser, device, gamma, page);

		expect(
			present(
				findSessionSetCookie(posted.headers.getSetCookie()),
				'the session cookie'
			)
		).toMatch(/;\s*Expires=/i);
	});

	it('approves a device the same way', async () => {
		await bindClientToBucket('acme-tv', acme.bucketId);
		const { device } = await holdingPasskey(acme);
		const started = await elysia.handle(
			new Request(`${acme.origin}${acme.prefix}/device/auth`, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					client_id: 'acme-tv',
					scope: 'openid'
				}).toString()
			})
		);
		const { device_code, user_code } = shaped(
			Type.Object({ device_code: Type.String(), user_code: Type.String() }),
			await started.json()
		);
		const browser = new Browser(acme.origin);
		const entry = await browser.request(`${acme.prefix}/device`);
		const xsrf = present(
			/name="xsrf" value="([0-9a-f]+)"/.exec(await entry.text())?.[1],
			'the device page’s xsrf'
		);
		const login = await browser.open(`${acme.prefix}/device`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ xsrf, user_code, confirm: 'yes' }).toString()
		});
		expect(login.url).toMatch(/\/ui\/[^/]+\/login$/);

		const posted = await postPasskey(browser, device, acme, {
			url: login.url,
			html: await login.response.text()
		});
		const consent = await browser.open(
			new URL(
				present(posted.headers.get('location'), 'a redirect'),
				login.url
			).toString()
		);
		const consentUid = present(
			/\/ui\/([^/]+)\/consent$/.exec(consent.url)?.[1],
			`a consent page (at ${consent.url})`
		);
		await browser.post(`/ui/${consentUid}/consent`, {
			action: 'allow',
			accountId: await shownAccount(consentUid)
		});
		const polled = await elysia.handle(
			new Request(`${acme.origin}${acme.prefix}/token`, {
				method: 'POST',
				headers: { 'content-type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams({
					client_id: 'acme-tv',
					grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
					device_code
				}).toString()
			})
		);

		const { id_token } = shaped(
			Type.Object({ id_token: Type.String() }),
			await polled.json()
		);
		expect(claimsOf(id_token).acr).toBe(MULTI_FACTOR);
	});

	it('answers a page older than its challenge with "Try again." and counts nothing', async () => {
		const { device } = await holdingPasskey(acme);
		await failuresFrom('203.0.113.10', 29);
		const browser = new Browser(acme.origin);
		const page = await signInPage(browser, acme);
		setSystemTime(new Date(Date.now() + 6 * 60 * 1000));

		const stale = await postPasskey(browser, device, acme, page);

		expect(textOf(await stale.text())).toContain('Try again.');
		expect((await refusedAttempt()).status).toBe(400);
		expect((await refusedAttempt()).status).toBe(429);
	});

	it('answers an attempt no page was shown for with "Try again." and counts nothing', async () => {
		await failuresFrom('203.0.113.14', 29);
		const browser = new Browser(acme.origin);
		const auth = new AuthorizationRequest({
			client_id: acme.clientId,
			scope: 'openid'
		});
		const started = await browser.request(
			`${acme.prefix}/auth?${encodeParams(auth.params)}`
		);
		const login = new URL(
			present(started.headers.get('location'), 'the sign-in page'),
			acme.origin
		).toString();
		const answer = await (
			await stranger()
		).get({ challenge: 'AAAA', rpId: 'e.ly' }, { origin: acme.origin });

		const unasked = await postCredential(
			browser,
			{ url: login },
			JSON.stringify(answer)
		);

		expect(textOf(await unasked.text())).toContain('Try again.');
		expect((await refusedAttempt()).status).toBe(400);
		expect((await refusedAttempt()).status).toBe(429);
	});

	it('spends the challenge on a refused attempt, so an answer to it sent afterwards signs nobody in', async () => {
		const { device } = await holdingPasskey(acme);
		const browser = new Browser(acme.origin);
		const page = await signInPage(browser, acme);
		const refused = await postPasskey(browser, await stranger(), acme, page);
		expect(refused.status).toBe(400);

		const replayed = await postPasskey(browser, device, acme, page);

		expect(replayed.status).toBe(400);
		expect(replayed.headers.get('location')).toBeNull();
	});

	it('answers a refusal with a page whose own fresh challenge the passkey then signs in with', async () => {
		const { device } = await holdingPasskey(acme);
		const browser = new Browser(acme.origin);
		const page = await signInPage(browser, acme);
		const refused = await postPasskey(browser, await stranger(), acme, page);

		const again = await postPasskey(browser, device, acme, {
			url: page.url,
			html: await refused.text()
		});

		expect(await codeAfter(browser, again, page.url)).toBeString();
	});

	it('refuses every attempt from an address with 30 failures this hour with 429, before looking anything up', async () => {
		const { device } = await holdingPasskey(acme);
		await failuresFrom('203.0.113.11', 30);
		const browser = new Browser(acme.origin);
		const page = await signInPage(browser, acme);

		const limited = await postPasskey(browser, device, acme, page);

		expect(limited.status).toBe(429);
		expect(limited.headers.get('retry-after')).toMatch(/^\d+$/);
		expect(textOf(await limited.text())).toContain(
			'Too many passkey attempts from your network. Try again later, or sign in another way.'
		);
	});

	it('lets the same passkey in from that address once the hour is over', async () => {
		const { device } = await holdingPasskey(acme);
		await failuresFrom('203.0.113.12', 30);
		setSystemTime(new Date(Date.now() + 61 * 60 * 1000));

		const { code } = await signInWithPasskey(
			new Browser(acme.origin),
			device,
			acme
		);

		expect(code).toBeString();
	});

	it('refuses a credential field that is no passkey answer in the same words as a passkey of no one here', async () => {
		const browser = new Browser(acme.origin);
		const page = await signInPage(browser, acme);

		const answered = await postCredential(browser, page, '{"not":"a passkey"}');

		expect(answered.status).toBe(400);
		expect(textOf(await answered.text())).toContain(
			'This passkey isn’t for Acme. Choose another one, or sign in another way.'
		);
	});

	it('never counts a successful sign-in among the failures', async () => {
		const { device } = await holdingPasskey(acme);
		await failuresFrom('203.0.113.13', 29);

		await signInWithPasskey(new Browser(acme.origin), device, acme);

		expect((await refusedAttempt()).status).toBe(400);
		expect((await refusedAttempt()).status).toBe(429);
	});
});
