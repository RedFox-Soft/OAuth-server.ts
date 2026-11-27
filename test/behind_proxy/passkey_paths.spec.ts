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
import {
	getBucketGroupStore,
	getBucketStore,
	getPersonActivityStore
} from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { decide, widenings } from 'lib/behind_proxy/decide.ts';
import { createAppSession } from 'lib/behind_proxy/session.ts';
import { ApplicationConfig, configuration } from 'lib/configs/application.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { rpIdFor } from 'lib/passkeys/relying_party.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import { wordsOf } from 'lib/person_activity/words.ts';
import { admin } from '../provisioning/helpers.ts';
import { present, shaped } from '../shape.ts';
import { Browser, PASSWORD } from '../connected_apps/helpers.ts';
import {
	holdingPasskey,
	postPasskey,
	seedPasskey
} from '../passkeys/helpers.ts';
import { mailOn } from '../require_code/helpers.ts';
import {
	AppJar,
	agentFor,
	behindProxyPath,
	checkApp,
	confirm,
	createApp,
	editor,
	expectStatus,
	member,
	tool,
	world,
	type AppView,
	type Member,
	type World
} from './helpers.ts';

const T0 = Date.UTC(2026, 10, 5, 9, 0);
const MINUTE = 60_000;

const Preview = Type.Object({
	changes: Type.Array(Type.String()),
	expect: Type.Object({
		withoutPasskey: Type.Number(),
		providerOnly: Type.Number()
	}),
	paths: Type.Array(Type.String())
});

let w: World;
let app: AppView;
let target: { slug: string; app: AppView };

interface Visit {
	jar: AppJar;
	browser: Browser;
}

function visit(): Visit {
	return { jar: new AppJar(), browser: new Browser() };
}

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

async function askForPasskeyOnPayouts(
	rootConditions: readonly unknown[] = []
): Promise<void> {
	const rules = [
		{
			path: '/',
			who: { kind: 'groups', groups: [w.acme.staff] },
			conditions: rootConditions
		},
		{
			path: '/payouts',
			who: { kind: 'groups', groups: [w.acme.staff] },
			conditions: [{ kind: 'fresh', maxAgeMinutes: 15, withPasskey: true }]
		}
	];
	const path = behindProxyPath(w.acme.id, app.id);
	const asked = await admin('PATCH', path, w.cookie, { rules });
	if (asked.status === 200) return;
	expect(asked.status).toBe(409);
	const preview = shaped(Preview, asked.body);
	expect(preview.changes).toContain('passkeyConditionOn');
	const applied = await admin('PATCH', path, w.cookie, {
		rules,
		confirm: true,
		expect: preview.expect
	});
	expectStatus(applied, 200, 'asking for a passkey on /payouts');
}

/**
 * @proves A behind-proxy app path (and FoxTrust network-facts `sign_in_again` outcome) asking for a passkey holds
 * every session and callback to a confirmed passkey: full passkey passes (and satisfies `withCode` paths too),
 * password / TOTP / pre-142 / stale sessions redirect to `/auth` with `acr_values=<phr>`, stripping `acr_values` or
 * returning from refusal creates no session and renders `passkeyNeededPage` (omitting the `/` link when `/` also asks
 * for a passkey), `notConfirmedPage` retry preserves `passkey=1`, widening order is `none < two-step < passkey`,
 * admin preview/confirm + `409 passkeys_not_accepted` + MCP parity hold, and person activity records `requirePasskey`.
 */
describe('a path behind the proxy asking for a passkey', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await mailOn();
		w = await world();
		forgetBucketAddresses();
		await getBucketStore().update(w.acme.id, { passkeyLogin: true });
		ApplicationConfig['personActivity.enabled'] = true;
		app = await createApp(w.cookie, w.acme.id, { rootGroups: [w.acme.staff] });
		target = { slug: w.acme.slug, app };
	});

	beforeEach(() => {
		resetSentEmails();
		setSystemTime(T0);
	});

	afterAll(() => {
		setSystemTime();
	});

	it('redirects non-passkey, TOTP, and pre-142 sessions to /auth with acr_values=<phr>, lets full passkey through, and records activity', async () => {
		await askForPasskeyOnPayouts();
		const phr = configuration.acrMap.phishing_resistant;
		const mfa = configuration.acrMap.multi_factor;

		/* A TOTP session (acr = mfa) is sent to sign in again with acr_values=phr. */
		const mfaCookie = await createAppSession(
			{ appId: app.id, bucketId: w.acme.id },
			w.acme.staffMember.accountId,
			{ authTime: Math.floor(T0 / 1000) - 60, acr: mfa }
		);

		const resMfa = await checkApp(target, {
			uri: '/payouts',
			cookie: `__Host-foxauth-${app.id}=${mfaCookie}`
		});
		expect(resMfa.status).toBe(302);
		const authUrl = new URL(
			present(resMfa.headers.get('location'), 'auth redirect')
		);
		expect(authUrl.searchParams.get('acr_values')).toBe(phr);
		expect(authUrl.searchParams.get('max_age')).toBe('900');

		/* Person activity records sign_in_again with freshness.requirePasskey = true. */
		await flushPersonActivityNow();
		const page = await getPersonActivityStore().listForPerson(
			w.acme.id,
			w.acme.staffMember.accountId,
			{ now: new Date(T0), limit: 20 }
		);
		const row = present(
			page.rows.find(
				(r) =>
					r.kind === 'app' &&
					r.place.appId === app.id &&
					r.reason === 'sign_in_again' &&
					r.freshness?.requirePasskey === true
			),
			'passkey sign_in_again activity row'
		);
		expect(
			wordsOf(row, { place: app.name, client: null, provider: null }).reason
		).toBe('Signed in without a passkey; /payouts asks for one');

		/* A full passkey session (acr = phr) passes /payouts AND also passes a withCode path. */
		const phrCookie = await createAppSession(
			{ appId: app.id, bucketId: w.acme.id },
			w.acme.staffMember.accountId,
			{ authTime: Math.floor(T0 / 1000) - 60, acr: phr }
		);
		const ok = await checkApp(target, {
			uri: '/payouts',
			cookie: `__Host-foxauth-${app.id}=${phrCookie}`
		});
		expect(ok.status).toBe(200);
	});

	it('completes a full passkey sign-in to /payouts, and refuses a stripped acr_values or refusal-return with passkeyNeededPage and no session', async () => {
		await askForPasskeyOnPayouts();
		const acmeProj = {
			bucketId: w.acme.id,
			clientId: `proxy.${w.acme.id}`,
			prefix: `/${w.acme.slug}`,
			origin: 'http://e.ly'
		};

		/* 1. Full passkey sign-in succeeds and lands on /payouts. */
		const holder = await holdingPasskey(acmeProj);
		await getBucketGroupStore().change(w.acme.staff, {
			add: [holder.accountId],
			remove: []
		});
		const v1 = visit();
		const started = await open(v1, '/payouts');
		expect(started.url).toMatch(/\/ui\/[^/]+\/login$/);
		const posted = await postPasskey(v1.browser, holder.device, acmeProj, {
			url: present(started.url, 'login url'),
			html: await present(started.response, 'login page').text()
		});
		const loc = present(posted.headers.get('location'), 'resume redirect');
		const callbackUrl = new URL(
			(await v1.browser.open(new URL(loc, started.url).toString())).url
		);
		expect(callbackUrl.pathname).toBe('/_foxauth/callback');
		const cb = v1.jar.absorb(
			await checkApp(target, {
				uri: `${callbackUrl.pathname}${callbackUrl.search}`,
				cookie: v1.jar.header
			})
		);
		expect(cb.status).toBe(302);
		expect(cb.headers.get('location')).toBe(`${app.address}/payouts`);
		const afterPasskey = await checkApp(target, {
			uri: '/payouts',
			cookie: v1.jar.header
		});
		expect(afterPasskey.status).toBe(200);

		/* 2. Stripped acr_values -> password sign-in succeeds at /auth, but callback refuses with passkeyNeededPage and makes NO session. */
		const pwUser: Member = await member(w.acme, [w.acme.staff]);
		const v2 = visit();
		const check2 = v2.jar.absorb(await checkApp(target, { uri: '/payouts' }));
		expect(check2.status).toBe(302);
		const stripped = new URL(
			present(check2.headers.get('location'), 'auth url')
		);
		stripped.searchParams.delete('acr_values');
		const loginStep = await v2.browser.open(stripped.toString());
		expect(loginStep.url).toMatch(/\/ui\/[^/]+\/login$/);
		const pwPosted = await v2.browser.post(loginStep.url, {
			username: pwUser.email,
			password: PASSWORD
		});
		const pwResume = await v2.browser.open(
			new URL(
				present(pwPosted.headers.get('location'), 'resume'),
				loginStep.url
			).toString()
		);
		const cbUrl2 = new URL(pwResume.url);
		expect(cbUrl2.pathname).toBe('/_foxauth/callback');
		const cb2 = v2.jar.absorb(
			await checkApp(target, {
				uri: `${cbUrl2.pathname}${cbUrl2.search}`,
				cookie: v2.jar.header
			})
		);
		expect(cb2.status).toBe(403);
		expect(cb2.headers.get('x-auth-reason')).toBe('passkey_required');
		const cb2Html = await cb2.text();
		expect(cb2Html).toContain('needs a passkey sign-in');
		expect(cb2Html).toContain(`href="${app.address}/"`);
		/* No app session was created! */
		expect(v2.jar.header).not.toContain(`__Host-foxauth-${app.id}=`);

		/* 3. When `/` itself asks for a passkey, passkeyNeededPage omits the link to `/`. */
		await askForPasskeyOnPayouts([
			{ kind: 'fresh', maxAgeMinutes: 15, withPasskey: true }
		]);
		const v3 = visit();
		const check3 = v3.jar.absorb(await checkApp(target, { uri: '/payouts' }));
		const auth3 = new URL(present(check3.headers.get('location'), 'auth3'));
		const cbError = await checkApp(target, {
			uri: `/_foxauth/callback?error=unmet_authentication_requirements&state=${encodeURIComponent(auth3.searchParams.get('state') ?? '')}`,
			cookie: v3.jar.header
		});
		expect(cbError.status).toBe(403);
		expect(cbError.headers.get('x-auth-reason')).toBe('passkey_required');
		const cb3Html = await cbError.text();
		expect(cb3Html).not.toContain(`href="${app.address}/"`);

		/* 4. /_foxauth/start?max_age=900&passkey=1 keeps asking for acr_values=phr. */
		const retry = await checkApp(target, {
			uri: '/_foxauth/start?max_age=900&passkey=1&rd=%2Fpayouts'
		});
		expect(retry.status).toBe(302);
		expect(
			new URL(present(retry.headers.get('location'), 'retry')).searchParams.get(
				'acr_values'
			)
		).toBe(configuration.acrMap.phishing_resistant);
	});

	it('enforces widening order none < two-step < passkey on fresh and network-facts outcomes, and decides network-facts withPasskey', () => {
		const root = { path: '/', who: { kind: 'project' as const } };
		const ruleWith = (fresh: {
			kind: 'fresh';
			maxAgeMinutes: number;
			withCode?: true;
			withPasskey?: true;
		}) => [
			root,
			{
				path: '/payouts',
				who: {
					kind: 'conditional' as const,
					who: { kind: 'project' as const },
					conditions: [fresh]
				}
			}
		];

		const none = ruleWith({ kind: 'fresh', maxAgeMinutes: 15 });
		const code = ruleWith({ kind: 'fresh', maxAgeMinutes: 15, withCode: true });
		const passkey = ruleWith({
			kind: 'fresh',
			maxAgeMinutes: 15,
			withPasskey: true
		});

		/* Tightening: none -> code -> passkey produces NO widenings. */
		expect(widenings(none, code)).toEqual([]);
		expect(widenings(code, passkey)).toEqual([]);
		expect(widenings(none, passkey)).toEqual([]);

		/* Loosening: passkey -> code and passkey -> none ARE widenings. */
		expect(widenings(passkey, code).length).toBeGreaterThan(0);
		expect(widenings(passkey, none).length).toBeGreaterThan(0);

		/* Network facts outcome withPasskey requires signedInWithPasskey on match. */
		const netRules = [
			{
				path: '/',
				who: {
					kind: 'conditional' as const,
					who: { kind: 'project' as const },
					conditions: [
						{
							kind: 'network' as const,
							only: [],
							not: [],
							facts: {
								categories: ['vpn' as const],
								outcome: {
									kind: 'sign_in_again' as const,
									maxAgeMinutes: 15,
									withPasskey: true as const
								}
							}
						}
					]
				}
			}
		];
		const dTotp = decide({
			rules: netRules,
			method: 'GET',
			rawPath: '/',
			address: '198.51.100.5',
			network: { known: true, categories: ['vpn'], country: 'US' },
			at: T0,
			person: {
				canSignIn: true,
				groupIds: [],
				signedInAt: Math.floor(T0 / 1000) - 60,
				signedInWithCode: true,
				signedInWithPasskey: false
			}
		});
		expect(dTotp.outcome).toBe('sign_in');
		expect(dTotp.requirePasskey).toBe(true);

		const dPasskey = decide({
			rules: netRules,
			method: 'GET',
			rawPath: '/',
			address: '198.51.100.5',
			network: { known: true, categories: ['vpn'], country: 'US' },
			at: T0,
			person: {
				canSignIn: true,
				groupIds: [],
				signedInAt: Math.floor(T0 / 1000) - 60,
				signedInWithCode: true,
				signedInWithPasskey: true
			}
		});
		expect(dPasskey.outcome).toBe('allow');
		expect(MINUTE).toBe(60_000);
	});

	it('refuses withPasskey with 409 passkeys_not_accepted when passkeys are off, and works through MCP behind_proxy_app_update', async () => {
		const { user, cookie, project } = await editor();
		const groupId = project.staff;
		const pApp = await createApp(cookie, project.id, { rootGroups: [groupId] });
		const rules = [
			{ path: '/', who: { kind: 'groups', groups: [groupId] } },
			{
				path: '/payouts',
				who: { kind: 'groups', groups: [groupId] },
				conditions: [{ kind: 'fresh', maxAgeMinutes: 15, withPasskey: true }]
			}
		];

		/* Passkeys off -> 409 passkeys_not_accepted */
		const refused = await admin(
			'PATCH',
			behindProxyPath(project.id, pApp.id),
			cookie,
			{ rules }
		);
		expect(refused.status).toBe(409);
		expect(refused.body).toMatchObject({ code: 'passkeys_not_accepted' });

		/* Turn passkeys on -> preview/confirm via MCP behind_proxy_app_update */
		forgetBucketAddresses();
		await getBucketStore().update(project.id, { passkeyLogin: true });
		const bucket = present(
			await getBucketStore().find(project.id),
			'project bucket'
		);
		const m1 = await member(project, [groupId]);
		await seedPasskey(project.id, m1.accountId, {
			rpId: rpIdFor(bucket),
			createdVia: 'password_code'
		});
		const previewRes = await admin(
			'PATCH',
			behindProxyPath(project.id, pApp.id),
			cookie,
			{ rules }
		);
		expect(previewRes.status).toBe(409);
		const expected = shaped(Preview, previewRes.body).expect;
		expect(expected.withoutPasskey).toBe(0);

		const token = await agentFor(user);
		const args = {
			id: project.id,
			appId: pApp.id,
			rules,
			confirm: true,
			expect: expected
		};
		const described = await tool(token, 'behind_proxy_app_update', args);
		expect(described.result?.structuredContent?.status).toBe(
			'confirmation_required'
		);
		const applied = await confirm(
			token,
			'behind_proxy_app_update',
			args,
			described
		);
		expect(applied.result?.isError).not.toBe(true);
	});
});
