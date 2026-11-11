import {
	afterAll,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { configuration } from 'lib/configs/application.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { admin } from '../provisioning/helpers.ts';
import { present, shaped } from '../shape.ts';
import {
	codeFor,
	linkIn,
	mailOn,
	propsOf,
	textOf,
	uidIn
} from '../require_code/helpers.ts';
import { Browser, PASSWORD } from '../connected_apps/helpers.ts';
import {
	AppJar,
	behindProxyPath,
	checkApp,
	createApp,
	expectStatus,
	member,
	world,
	type AppView,
	type Member,
	type World
} from './helpers.ts';

const SECRET = 'JBSWY3DPEHPK3PXP';
const T0 = Date.UTC(2026, 10, 5, 9, 0);
const MINUTE = 60_000;
const JSON_ACCEPT = 'application/json';

const Preview = Type.Object({
	expect: Type.Object({
		withoutAuthenticator: Type.Number(),
		providerOnly: Type.Number()
	})
});

let w: World;
let app: AppView;
let target: { slug: string; app: AppView };

async function holdsFactor(who: Member): Promise<void> {
	await getUserStore(w.acme.id).update(who.accountId, {
		totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0, via: 'self' }
	});
}

/* Rules as the admin routes take them: the app for Staff, and /admin asking a sign-in with a code within 15 minutes. */
async function askForCodeOnAdmin(root: readonly unknown[] = []): Promise<void> {
	const rules = [
		{
			path: '/',
			who: { kind: 'groups', groups: [w.acme.staff] },
			conditions: root
		},
		{
			path: '/admin',
			who: { kind: 'groups', groups: [w.acme.staff] },
			conditions: [{ kind: 'fresh', maxAgeMinutes: 15, withCode: true }]
		}
	];
	const path = behindProxyPath(w.acme.id, app.id);
	const asked = await admin('PATCH', path, w.cookie, { rules });
	if (asked.status === 200) return;
	expect(asked.status).toBe(409);
	const applied = await admin('PATCH', path, w.cookie, {
		rules,
		confirm: true,
		expect: shaped(Preview, asked.body).expect
	});
	expectStatus(applied, 200, 'asking for a code on /admin');
}

interface Visit {
	jar: AppJar;
	browser: Browser;
}

function visit(): Visit {
	return { jar: new AppJar(), browser: new Browser() };
}

/* A navigation to the app, as the proxy checks it; a redirect to sign in is followed to the first page that stops it. */
async function open(
	v: Visit,
	uri: string
): Promise<{ check: Response; url?: string; response?: Response }> {
	const check = v.jar.absorb(
		await checkApp(target, { uri, cookie: v.jar.header })
	);
	if (check.status !== 302) return { check };
	const step = await v.browser.open(
		present(check.headers.get('location'), 'a sign-in')
	);
	return { check, ...step };
}

/* Types the password on the login page, and the code when the sign-in asks for one; answers where that led. */
async function signIn(
	v: Visit,
	loginUrl: string,
	who: Member,
	secret?: string
): Promise<{ url: string; response: Response }> {
	expect(loginUrl).toMatch(/\/ui\/[^/]+\/login$/);
	const posted = await v.browser.post(loginUrl, {
		username: who.email,
		password: PASSWORD
	});
	let step = await v.browser.open(
		new URL(
			present(posted.headers.get('location'), 'a redirect'),
			loginUrl
		).toString()
	);
	if (secret && /\/ui\/[^/]+\/totp$/.test(step.url)) {
		const answered = await v.browser.post(step.url, { code: codeFor(secret) });
		step = await v.browser.open(
			new URL(
				present(answered.headers.get('location'), 'a resume'),
				step.url
			).toString()
		);
	}
	return step;
}

/* The callback relayed to the check, as the proxy relays it. */
async function relay(v: Visit, callbackUrl: string): Promise<Response> {
	const callback = new URL(callbackUrl);
	expect(callback.pathname).toBe('/_foxauth/callback');
	return v.jar.absorb(
		await checkApp(target, {
			uri: `${callback.pathname}${callback.search}`,
			cookie: v.jar.header
		})
	);
}

/* The whole sign-in from a navigation to `uri`, through the callback; answers the check's last answer. */
async function signInFrom(
	v: Visit,
	uri: string,
	who: Member,
	secret?: string
): Promise<Response> {
	const opened = await open(v, uri);
	const landed = await signIn(v, present(opened.url, 'a login'), who, secret);
	return relay(v, landed.url);
}

function allowed(v: Visit, uri: string): Promise<Response> {
	return checkApp(target, { uri, cookie: v.jar.header, accept: JSON_ACCEPT });
}

describe('a path behind the proxy that asks for a code', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		await mailOn();
		app = await createApp(w.cookie, w.acme.id, { rootGroups: [w.acme.staff] });
		target = { slug: w.acme.slug, app };
		await askForCodeOnAdmin();
	});

	beforeEach(() => {
		resetSentEmails();
	});

	afterAll(() => {
		setSystemTime();
	});

	/**
	 * @proves A person who holds a code opens a path that asks for a recent sign-in with one: an older sign-in, even
	 * a multi-factor one, sends them to sign in with their password and their code, and then the path opens until the
	 * interval runs out.
	 */
	describe('a person with a code', () => {
		it('signs in again with the password and the code when the sign-in with a code is older than asked', async () => {
			const who = await member(w.acme, [w.acme.staff]);
			await holdsFactor(who);
			const v = visit();
			setSystemTime(T0);
			const first = await signInFrom(v, '/', who, SECRET);
			expect(first.status).toBe(302);
			setSystemTime(T0 + 20 * MINUTE);

			const opened = await open(v, '/admin');
			const sent = new URL(
				present(opened.check.headers.get('location'), 'a sign-in')
			);
			expect(sent.searchParams.get('max_age')).toBe('900');
			expect(sent.searchParams.get('acr_values')).toBe(
				configuration.acrMap.multi_factor
			);
			const login = present(opened.url, 'the login page');
			const notices = textOf(await present(opened.response, 'a page').text());
			const landed = await signIn(v, login, who, SECRET);
			const completed = await relay(v, landed.url);

			expect(notices).toContain(
				'asks you to sign in again with a code from an authenticator app to open this page.'
			);
			expect(notices).not.toContain('The app you’re signing in to asks');
			expect(completed.status).toBe(302);
			expect(completed.headers.get('location')).toBe(`${app.address}/admin`);
			expect((await allowed(v, '/admin')).status).toBe(200);
			setSystemTime(T0 + 30 * MINUTE);
			expect((await allowed(v, '/admin')).status).toBe(200);
		});

		it('is sent to sign in with a code when the app session came from a sign-in without one', async () => {
			const who = await member(w.acme, [w.acme.staff]);
			const v = visit();
			setSystemTime(T0);
			await signInFrom(v, '/', who);
			await holdsFactor(who);
			setSystemTime(T0 + MINUTE);

			const background = await allowed(v, '/admin');
			const opened = await open(v, '/admin');
			const landed = await signIn(
				v,
				present(opened.url, 'a login'),
				who,
				SECRET
			);
			const completed = await relay(v, landed.url);

			expect(background.status).toBe(401);
			expect(background.headers.get('x-auth-reason')).toBe('sign_in_again');
			expect(completed.headers.get('location')).toBe(`${app.address}/admin`);
			expect((await allowed(v, '/admin')).status).toBe(200);
		});

		it('is asked for the code at the first sign-in to the path, not after a sign-in without one', async () => {
			const who = await member(w.acme, [w.acme.staff]);
			await holdsFactor(who);
			const v = visit();
			setSystemTime(T0);

			const opened = await open(v, '/admin');

			const sent = new URL(
				present(opened.check.headers.get('location'), 'a sign-in')
			);
			expect(sent.searchParams.get('acr_values')).toBe(
				configuration.acrMap.multi_factor
			);
			const completed = await relay(
				v,
				(await signIn(v, present(opened.url, 'a login'), who, SECRET)).url
			);
			expect(completed.headers.get('location')).toBe(`${app.address}/admin`);
		});
	});

	/**
	 * @proves The proxy opens a path that asks for a code only on a code whose sign-in included one and is recent
	 * enough, whatever the request to the sign-in carried; a retry keeps both requirements, and nothing loops.
	 */
	describe('the callback', () => {
		it('makes no session from a sign-in without a code, even with the request for one taken off', async () => {
			const who = await member(w.acme, [w.acme.staff]);
			const v = visit();
			setSystemTime(T0);
			const sent = v.jar.absorb(await checkApp(target, { uri: '/admin' }));
			const toProject = new URL(
				present(sent.headers.get('location'), 'a sign-in')
			);
			toProject.searchParams.delete('acr_values');

			const opened = await v.browser.open(toProject.toString());
			const landed = await signIn(v, opened.url, who);
			const returned = await relay(v, landed.url);
			const page = textOf(await returned.text());

			expect(returned.status).toBe(403);
			expect(returned.headers.get('x-auth-reason')).toBe('code_required');
			expect(returned.headers.getSetCookie().join(';')).not.toContain(
				`__Host-foxauth-${app.id}=`
			);
			expect(page).toContain('needs a code from an authenticator app');
			expect(page).not.toContain('Sign in again');
		});

		it('offers a retry that keeps the code when the sign-in with a code came back older than asked', async () => {
			const who = await member(w.acme, [w.acme.staff]);
			await holdsFactor(who);
			const v = visit();
			setSystemTime(T0);
			await signInFrom(v, '/', who, SECRET);
			setSystemTime(T0 + 20 * MINUTE);
			const sent = v.jar.absorb(
				await checkApp(target, { uri: '/admin', cookie: v.jar.header })
			);
			const toProject = new URL(
				present(sent.headers.get('location'), 'a sign-in')
			);
			toProject.searchParams.delete('max_age');

			const step = await v.browser.open(toProject.toString());
			const returned = await relay(v, step.url);
			const retry = present(
				/href="([^"]*\/_foxauth\/start[^"]*)"/.exec(await returned.text())?.[1],
				'a retry link'
			).replace(/&amp;/g, '&');

			expect(returned.headers.get('x-auth-reason')).toBe('sign_in_not_fresh');
			expect(retry).toContain('max_age=900');
			expect(retry).toContain('code=1');
			const again = v.jar.absorb(
				await checkApp(target, { uri: retry, cookie: v.jar.header })
			);
			expect(
				new URL(
					present(again.headers.get('location'), 'a sign-in')
				).searchParams.get('acr_values')
			).toBe(configuration.acrMap.multi_factor);
		});
	});

	/**
	 * @proves A person without a code who opens a path that asks for one is not looped: the sign-in stops on a page
	 * that names the app by its host and lets them set one up and reach the path in the same sign-in, or, where they
	 * cannot, go back to a page that says what the path needs and starts nothing.
	 */
	describe('a person without a code', () => {
		it('sets one up from the refusal page and reaches the path in the same sign-in', async () => {
			const who = await member(w.acme, [w.acme.staff]);
			const v = visit();
			setSystemTime(T0);

			const opened = await open(v, '/admin');
			const refused = await signIn(v, present(opened.url, 'a login'), who);
			expect(refused.url).toMatch(/\/ui\/[^/]+\/code-required$/);
			const shown = textOf(await refused.response.text());
			expect(shown).toContain(
				`${new URL(app.address).host} asks for a code from an authenticator app`
			);
			const uid = uidIn(refused.url);
			await v.browser.open(`/ui/${uid}/totp/enroll`);
			await v.browser.open(linkIn(who.email, `/ui/${uid}/totp/enroll/link`));
			const enrol = await v.browser.request(`/ui/${uid}/totp/enroll`);
			const secret = String(propsOf(await enrol.text()).secretText).replace(
				/\s+/g,
				''
			);
			const confirmed = await v.browser.post(`/ui/${uid}/totp/enroll`, {
				code: codeFor(secret)
			});
			const landed = await v.browser.open(
				new URL(
					present(confirmed.headers.get('location'), 'a resume'),
					v.browser.url(`/ui/${uid}/`)
				).toString()
			);
			const completed = await relay(v, landed.url);

			expect(completed.headers.get('location')).toBe(`${app.address}/admin`);
			expect((await allowed(v, '/admin')).status).toBe(200);
		});

		it('ends on a page that says what the path needs, with no way to start the same sign-in, after going back', async () => {
			const who = await member(w.acme, [w.acme.staff]);
			const v = visit();
			setSystemTime(T0);
			await getBucketStore().update(w.acme.id, { totpSelfService: false });
			forgetBucketAddresses();
			try {
				const opened = await open(v, '/admin');
				const refused = await signIn(v, present(opened.url, 'a login'), who);
				const shown = textOf(await refused.response.text());
				const back = await v.browser.post(refused.url, { action: 'return' });
				const landed = await v.browser.open(
					new URL(
						present(back.headers.get('location'), 'a resume'),
						refused.url
					).toString()
				);
				const returned = await relay(v, landed.url);
				const page = await returned.text();

				expect(shown).toContain('Ask the people who run');
				expect(shown).not.toContain('Set up an authenticator app');
				expect(returned.status).toBe(403);
				expect(returned.headers.get('x-auth-reason')).toBe('code_required');
				expect(textOf(page)).toContain(
					'needs a code from an authenticator app'
				);
				expect(page).not.toContain('/_foxauth/start');
				expect(page).toContain(`href="${app.address}/"`);
			} finally {
				await getBucketStore().update(w.acme.id, {
					totpSelfService: undefined
				});
				forgetBucketAddresses();
			}
		});

		it('is offered no link to the start page when the start page asks for a code too', async () => {
			await askForCodeOnAdmin([
				{ kind: 'fresh', maxAgeMinutes: 480, withCode: true }
			]);
			const who = await member(w.acme, [w.acme.staff]);
			const v = visit();
			setSystemTime(T0);
			try {
				const opened = await open(v, '/admin');
				const refused = await signIn(v, present(opened.url, 'a login'), who);
				const back = await v.browser.post(refused.url, { action: 'return' });
				const landed = await v.browser.open(
					new URL(
						present(back.headers.get('location'), 'a resume'),
						refused.url
					).toString()
				);
				const page = await (await relay(v, landed.url)).text();

				expect(page).not.toContain(`href="${app.address}/"`);
				expect(page).not.toContain('/_foxauth/start');
			} finally {
				await askForCodeOnAdmin();
			}
		});

		it('is shown the page that says what the path needs in the person’s language', async () => {
			const who = await member(w.acme, [w.acme.staff]);
			const v = visit();
			setSystemTime(T0);
			const sent = v.jar.absorb(await checkApp(target, { uri: '/admin' }));
			const toProject = new URL(
				present(sent.headers.get('location'), 'a sign-in')
			);
			toProject.searchParams.delete('acr_values');
			const opened = await v.browser.open(toProject.toString());
			const landed = await signIn(v, opened.url, who);

			const returned = await checkApp(target, {
				uri: `${new URL(landed.url).pathname}${new URL(landed.url).search}`,
				cookie: v.jar.header,
				headers: { 'Accept-Language': 'ru' }
			});

			expect(textOf(await returned.text())).toContain(
				'нужен код из приложения-аутентификатора'
			);
		});
	});
});
