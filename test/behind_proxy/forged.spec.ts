import {
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { ApplicationConfig } from 'lib/configs/application.ts';
import { setPeerResolverForTests } from 'lib/helpers/caller_address.ts';
import { resetUnauthenticatedCharge } from 'lib/helpers/unauthenticated_charge.ts';
import {
	resetCheckRateLimiter,
	setCheckRateBoundsForTests
} from 'lib/behind_proxy/rate_limit.ts';
import { present } from '../shape.ts';
import {
	AppJar,
	answerOf,
	check,
	checkApp,
	createApp,
	group,
	hostOf,
	markerCookieName,
	member,
	reachCallback,
	relayCallback,
	sessionCookieName,
	setRules,
	signInThrough,
	world,
	type AppView,
	type World
} from './helpers.ts';

/* Not a page navigation, so a request with no usable session is answered `401` rather than sent to sign-in. */
const API = 'application/json';

const IDENTITY = [
	'x-auth-user',
	'x-auth-email',
	'x-auth-groups',
	'x-auth-assertion'
];

/**
 * @proves Nothing a browser or an outside caller sends talks the check into a wrong answer: a reported host that
 * is not the app's address, another app's session cookie, a crafted return address, a sign-in completion without
 * the browser's own marker or a second time, an identity header the client wrote, and a value that would break a
 * header are each refused or ignored; and a flood of checks for one app slows only that app, charged to the proxy
 * that sent them rather than to whatever address it reports for the person.
 */
describe('a check a browser or an outside caller tries to forge', () => {
	let w: World;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	async function staffApp(): Promise<{ slug: string; app: AppView }> {
		const app = await createApp(w.cookie, w.acme.id, {
			rootGroups: [w.acme.staff]
		});
		return { slug: w.acme.slug, app };
	}

	describe('a check for app A', () => {
		it.each([
			['another host', (host: string) => `elsewhere.${host}`],
			['another port', (host: string) => `${host}:8443`],
			['a list of hosts', (host: string) => `evil.example.com, ${host}`],
			['a host with a suffix', (host: string) => `${host}.evil.example`]
		])(
			'a reported host other than A’s address is refused exactly like an unknown app: %s',
			async (_what, forge) => {
				const target = await staffApp();
				const { cookie } = await signInThrough(target, w.acme.staffMember);
				const host = hostOf(target.app.address);
				const unknown = await answerOf(
					await check({ slug: w.acme.slug, appId: 'no-such-app', host })
				);

				const res = await answerOf(
					await checkApp(target, { host: forge(host), uri: '/reports', cookie })
				);

				expect(res).toEqual(unknown);
			}
		);
	});

	describe('two apps of one project', () => {
		it.each([
			[
				"under A's cookie name",
				(a: string, _b: string) => sessionCookieName(a)
			],
			["under B's cookie name", (_a: string, b: string) => sessionCookieName(b)]
		])(
			'app A’s session cookie is refused at app B: %s',
			async (_what, nameFor) => {
				const a = await staffApp();
				const b = await staffApp();
				const { jar } = await signInThrough(a, w.acme.staffMember);
				const value = present(
					jar.get(sessionCookieName(a.app.id)),
					'A’s cookie'
				);

				const res = await checkApp(b, {
					uri: '/reports',
					cookie: `${nameFor(a.app.id, b.app.id)}=${value}`,
					accept: API
				});

				expect(res.status).toBe(401);
				expect(res.headers.get('x-auth-reason')).toBe('no_session');
			}
		);
	});

	describe('a public path', () => {
		it('the allowed answer carries every identity header, empty, whatever the request carried', async () => {
			const target = await staffApp();
			await setRules(w.cookie, w.acme.id, target.app.id, [
				{ path: '/', who: { kind: 'groups', groups: [w.acme.staff] } },
				{ path: '/status', who: { kind: 'public', subtree: false } }
			]);
			const { cookie } = await signInThrough(target, w.acme.staffMember);

			const res = await checkApp(target, {
				uri: '/status',
				cookie,
				headers: {
					'X-Auth-User': 'root',
					'X-Auth-Email': 'root@example.com',
					'X-Auth-Groups': 'admins'
				}
			});

			expect(res.status).toBe(200);
			expect(res.headers.get('x-auth-reason')).toBe('public');
			expect(IDENTITY.map((name) => [name, res.headers.get(name)])).toEqual(
				IDENTITY.map((name) => [name, ''])
			);
		});
	});

	describe('a sign-in started with a return address on another origin', () => {
		it.each([
			['an absolute address', 'https://evil.example.com/x'],
			['a scheme-relative address', '//evil.example.com/x'],
			['a backslash address', '/\\evil.example.com/x'],
			[
				'an address with a user name',
				'https://evil.example.com@app.example.com/x'
			],
			['a script address', 'javascript:alert(1)']
		])('the person returns to the app’s root: %s', async (_what, rd) => {
			const target = await staffApp();

			const { landedAt } = await signInThrough(target, w.acme.staffMember, {
				from: `/_foxauth/start?rd=${encodeURIComponent(rd)}`
			});

			expect(landedAt).toBe(`${target.app.address}/`);
		});
	});

	describe('a sign-in completion', () => {
		it('without the browser’s marker it is refused and no session is created', async () => {
			const target = await staffApp();
			const { callback } = await reachCallback(target, w.acme.staffMember);

			const res = await relayCallback(target, callback, '');

			expect(res.status).toBe(403);
			expect(res.headers.get('x-auth-reason')).toBe('sign_in_failed');
			expect(res.headers.getSetCookie()).toEqual([]);
		});

		it('with another sign-in’s marker it is refused and no session is created', async () => {
			const target = await staffApp();
			const victim = new AppJar();
			victim.absorb(await checkApp(target, { uri: '/' }));
			const { callback } = await reachCallback(target, w.acme.outsider);

			const res = await relayCallback(target, callback, victim.header);

			expect(res.status).toBe(403);
			expect(res.headers.get('x-auth-reason')).toBe('sign_in_failed');
			expect(res.headers.getSetCookie()).toEqual([]);
		});

		it('a second use of the same state is refused', async () => {
			const target = await staffApp();
			const { callback, jar } = await reachCallback(target, w.acme.staffMember);
			const marker = `${markerCookieName(target.app.id)}=${present(
				jar.get(markerCookieName(target.app.id)),
				'the sign-in marker'
			)}`;
			expect((await relayCallback(target, callback, marker)).status).toBe(302);

			const again = await relayCallback(target, callback, marker);

			expect(again.status).toBe(403);
			expect(again.headers.get('x-auth-reason')).toBe('sign_in_failed');
			expect(again.headers.getSetCookie()).toEqual([]);
		});
	});

	describe('a person whose email or group name holds a line break', () => {
		it('the check refuses instead of answering when it is the email', async () => {
			const target = await staffApp();
			const person = await member(w.acme, [w.acme.staff]);
			const { cookie } = await signInThrough(target, person);
			await getUserStore(w.acme.id).update(person.accountId, {
				email: `${person.email}\r\nX-Auth-User: root`
			});
			/* Past the minute a person's standing is kept for. */
			setSystemTime(new Date(Date.now() + 61_000));

			try {
				const res = await checkApp(target, { uri: '/', cookie, accept: API });

				expect(res.status).toBe(403);
				expect(res.headers.get('x-auth-reason')).toBe('unsafe_value');
				expect(res.headers.get('x-auth-user')).toBeNull();
			} finally {
				setSystemTime();
			}
		});

		it('the check refuses instead of answering when it is a group name', async () => {
			const target = await staffApp();
			const person = await member(w.acme, [w.acme.staff]);
			await group(w.acme.id, 'Ops\nX-Auth-Groups: admins', [person.accountId]);
			const { cookie } = await signInThrough(target, person);

			const res = await checkApp(target, { uri: '/', cookie, accept: API });

			expect(res.status).toBe(403);
			expect(res.headers.get('x-auth-reason')).toBe('unsafe_value');
		});
	});

	describe('checks over one app’s limit', () => {
		afterEach(() => {
			setCheckRateBoundsForTests(null);
			resetCheckRateLimiter();
		});

		it('that app’s checks are slowed and another app’s are not', async () => {
			const open = async () => {
				const target = await staffApp();
				await setRules(w.cookie, w.acme.id, target.app.id, [
					{ path: '/', who: { kind: 'public', subtree: true } }
				]);
				return target;
			};
			const flooded = await open();
			const other = await open();
			setCheckRateBoundsForTests({ max: 3, windowSeconds: 60 });
			for (let i = 0; i < 3; i++) {
				expect((await checkApp(flooded, { uri: '/' })).status).toBe(200);
			}

			const slowed = await checkApp(flooded, { uri: '/' });
			const untouched = await checkApp(other, { uri: '/' });

			expect(slowed.status).toBe(429);
			expect(slowed.headers.get('x-auth-reason')).toBe('rate_limited');
			expect(untouched.status).toBe(200);
		});
	});

	describe('checks carrying X-Forwarded-For from a proxy the instance trusts', () => {
		const strict = ApplicationConfig['rateLimit.strict.max'];

		afterEach(() => {
			ApplicationConfig['rateLimit.strict.max'] = strict;
			setPeerResolverForTests(null);
			resetUnauthenticatedCharge();
		});

		it('the forwarded address is not the caller address for the instance’s limits', async () => {
			const target = await staffApp();
			resetUnauthenticatedCharge();
			ApplicationConfig['rateLimit.strict.max'] = 3;
			setPeerResolverForTests(() => '10.0.0.5');
			const probe = (person: number) =>
				check({
					slug: w.acme.slug,
					appId: 'no-such-app',
					host: hostOf(target.app.address),
					headers: { 'X-Forwarded-For': `203.0.113.${String(person)}` }
				});
			for (let person = 1; person <= 3; person++) {
				expect((await probe(person)).status).toBe(403);
			}

			const fourth = await probe(4);

			expect(fourth.status).toBe(429);
		});
	});
});
