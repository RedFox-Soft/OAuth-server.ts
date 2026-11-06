import {
	afterAll,
	beforeAll,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap from '../test_helper.js';
import { getUserStore } from 'lib/adapters/index.ts';
import { decide, type Person } from 'lib/behind_proxy/decide.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	behindProxyPath,
	createApp,
	member,
	signInThrough,
	world,
	type AppView,
	type Member,
	type World
} from './helpers.ts';
import {
	fromProxy,
	issueProxyKey,
	keyedCheck,
	proveAddresses
} from './conditions_helpers.ts';
import {
	edgeRules,
	MOMENTS,
	NOT_TEST_NET,
	NETWORK,
	ROWS,
	rowName,
	storedRules,
	ZONE,
	type Row,
	type Who
} from './conditions_table.ts';

const STATUS = { allow: 200, deny: 403, sign_in: 401 } as const;
const JSON_ACCEPT = 'application/json';

let w: World;
let key: string;
let adminOps: Member;
let adminSales: Member;
const apps = new Map<string, AppView>();

async function withDepartment(who: Member, department: string): Promise<void> {
	await getUserStore(w.acme.id).update(who.accountId, {
		profile: { enterprise: { department } }
	});
}

async function appFor(root: Row['root']): Promise<AppView> {
	const name = root === NOT_TEST_NET ? 'not' : 'only';
	const known = apps.get(name);
	if (known) return known;
	const app = await createApp(w.cookie, w.acme.id, {
		rootGroups: [w.acme.staff]
	});
	await proveAddresses({ slug: w.acme.slug, app }, key);
	const reply = await admin(
		'PATCH',
		behindProxyPath(w.acme.id, app.id),
		w.cookie,
		{
			timeZone: ZONE,
			rules: edgeRules(
				{ staff: w.acme.staff, admins: w.acme.admins },
				root ?? NETWORK
			)
		}
	);
	expect(reply.status).toBe(200);
	apps.set(name, app);
	return app;
}

function memberOf(who: Who): Member | null {
	if (who === 'none') return null;
	if (who === 'staff') return w.acme.staffMember;
	return who === 'adminOps' ? adminOps : adminSales;
}

function personOf(row: Row): Person | null {
	const who = memberOf(row.who);
	if (!who) return null;
	return {
		canSignIn: true,
		groupIds: row.who === 'staff' ? [w.acme.staff] : [w.acme.admins],
		attributes:
			row.who === 'adminOps'
				? { department: 'Ops' }
				: row.who === 'adminSales'
					? { department: 'Sales' }
					: {},
		signedInAt: Math.floor(
			(MOMENTS[row.at] - (row.signedInAgo ?? 0) * 60_000) / 1000
		)
	};
}

/**
 * @proves Where a request comes from, when it arrives, what the person's department is and how recently they signed
 * in decide access exactly as quickstart §2 says — through the live check and through the console's "Check access",
 * which reach the same decision for the same inputs.
 */
describe('conditions on an app behind the proxy', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		key = (await issueProxyKey(w.cookie, w.acme.id)).key;
		adminOps = await member(w.acme, [w.acme.admins]);
		adminSales = await member(w.acme, [w.acme.admins]);
		await withDepartment(adminOps, 'Ops');
		await withDepartment(adminSales, 'Sales');
	});

	afterAll(() => {
		setSystemTime();
	});

	describe('the decision table', () => {
		it.each(ROWS.map((row) => [rowName(row), row] as const))(
			'%s is decided as the table says, live',
			async (_name, row) => {
				const app = await appFor(row.root);
				const target = { slug: w.acme.slug, app };
				const who = memberOf(row.who);
				let cookie: string | undefined;
				if (who) {
					setSystemTime(MOMENTS[row.at] - (row.signedInAgo ?? 0) * 60_000);
					cookie = (
						await signInThrough(target, who, {
							from: '/',
							headers: fromProxy(key, '203.0.113.9')
						})
					).cookie;
				}
				setSystemTime(MOMENTS[row.at]);

				const response = await keyedCheck(
					target,
					row.address === null ? null : key,
					row.address,
					{
						uri: row.uri,
						cookie,
						accept: JSON_ACCEPT
					}
				);

				expect(response.headers.get('x-auth-reason')).toBe(row.reason);
				expect(response.status).toBe(STATUS[row.outcome]);
			}
		);

		it.each(ROWS.map((row) => [rowName(row), row] as const))(
			'%s is decided as the table says, in the console',
			(_name, row) => {
				const decision = decide({
					rules: storedRules(
						{ staff: w.acme.staff, admins: w.acme.admins },
						row.root ?? NETWORK
					),
					method: 'GET',
					rawPath: row.uri,
					person: personOf(row),
					address: row.address,
					at: MOMENTS[row.at],
					timeZone: ZONE
				});

				expect(decision.reason).toBe(row.reason);
				expect(decision.outcome).toBe(row.outcome);
			}
		);
	});

	describe('a refused navigation', () => {
		it('names no range and offers no other account when refused by network, while a group refusal still offers one', async () => {
			const app = await appFor(undefined);
			const target = { slug: w.acme.slug, app };
			setSystemTime(MOMENTS.thu1400);

			const byNetwork = await keyedCheck(target, key, '192.0.2.5', {
				uri: '/dash'
			});
			const page = await byNetwork.text();
			const signedIn = await signInThrough(target, w.acme.outsider, {
				from: '/',
				headers: fromProxy(key, '203.0.113.9')
			});
			const byGroup = await keyedCheck(target, key, '203.0.113.9', {
				uri: '/dash',
				cookie: signedIn.cookie
			});

			expect(byNetwork.status).toBe(403);
			expect(page).not.toContain('203.0.113');
			expect(page).not.toContain('/_foxauth/sign_out');
			expect(byGroup.status).toBe(403);
			expect(await byGroup.text()).toContain('/_foxauth/sign_out');
		});
	});

	describe('"Check access" without a network address', () => {
		it('shows the network condition as unknown and every other condition with its real result', () => {
			const decision = decide({
				rules: storedRules({ staff: w.acme.staff, admins: w.acme.admins }),
				method: 'GET',
				rawPath: '/admin',
				person: personOf({
					uri: '/admin',
					address: null,
					at: 'sat1400',
					who: 'adminOps',
					signedInAgo: 3,
					outcome: 'deny',
					reason: 'outside_hours'
				}),
				address: null,
				at: MOMENTS.sat1400,
				timeZone: ZONE,
				explain: true
			});

			expect(
				decision.conditions?.map((c) => [c.kind, c.from, c.result])
			).toEqual([
				['network', '/', 'unknown'],
				['time', '/', 'fail'],
				['attribute', '/admin', 'pass'],
				['fresh', '/admin', 'pass']
			]);
			expect(decision.reason).toBe('outside_hours');
		});
	});
});

/**
 * @proves A network condition cannot be saved until the proxy has shown it passes people's addresses, so one save
 * cannot turn everyone away or trust an address a browser wrote.
 */
describe('saving a network condition', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
	});

	const rules = (staff: string) => [
		{
			path: '/',
			who: { kind: 'groups', groups: [staff] },
			conditions: [NETWORK]
		}
	];

	it('is refused while the proxy never proved it passes addresses', async () => {
		const app = await createApp(w.cookie, w.acme.id, {
			rootGroups: [w.acme.staff]
		});

		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			{
				rules: rules(w.acme.staff)
			}
		);

		expect(reply.status).toBe(409);
		expect((reply.body as { code: string }).code).toBe(
			'proxy_address_unproven'
		);
	});

	it('succeeds after a keyed check from a public address', async () => {
		const app = await createApp(w.cookie, w.acme.id, {
			rootGroups: [w.acme.staff]
		});
		const issued = await issueProxyKey(w.cookie, w.acme.id);
		await proveAddresses({ slug: w.acme.slug, app }, issued.key);

		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			{
				rules: rules(w.acme.staff)
			}
		);

		expect(reply.status).toBe(200);
	});
});

/**
 * @proves A path that asks for a recent sign-in sends a person who signed in long ago to sign in again and back to the
 * page, refuses a sign-in that comes back older than it asked — however the request to the project was altered — and
 * leaves the session it replaced unable to open anything.
 */
describe('a path that asks for a recent sign-in', () => {
	let app: AppView;
	const T0 = Date.UTC(2026, 10, 5, 9, 0);

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		app = await createApp(w.cookie, w.acme.id, { rootGroups: [w.acme.staff] });
		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			{
				rules: [
					{
						path: '/',
						who: { kind: 'groups', groups: [w.acme.staff] },
						conditions: [{ kind: 'fresh', maxAgeMinutes: 15 }]
					}
				]
			}
		);
		expect(reply.status).toBe(200);
	});

	afterAll(() => {
		setSystemTime();
	});

	it('sends a navigation to sign in again with the age it asks for, and a background request gets 401', async () => {
		const target = { slug: w.acme.slug, app };
		setSystemTime(T0);
		const signedIn = await signInThrough(target, w.acme.staffMember);
		setSystemTime(T0 + 20 * 60_000);

		const navigation = await keyedCheck(target, null, null, {
			uri: '/dash',
			cookie: signedIn.cookie
		});
		const background = await keyedCheck(target, null, null, {
			uri: '/api/data',
			cookie: signedIn.cookie,
			accept: JSON_ACCEPT
		});

		expect(navigation.status).toBe(302);
		expect(
			new URL(navigation.headers.get('location') ?? '').searchParams.get(
				'max_age'
			)
		).toBe('900');
		expect(background.status).toBe(401);
		expect(background.headers.get('x-auth-reason')).toBe('sign_in_again');
	});

	it('returns the person to the page after signing in again, and the session it replaced opens nothing', async () => {
		const target = { slug: w.acme.slug, app };
		setSystemTime(T0);
		const first = await signInThrough(target, w.acme.staffMember);
		setSystemTime(T0 + 20 * 60_000);

		const again = await signInThrough(target, w.acme.staffMember, {
			from: '/dash',
			browser: first.browser,
			jar: first.jar
		});
		const withOld = await keyedCheck(target, null, null, {
			uri: '/dash',
			cookie: first.cookie,
			accept: JSON_ACCEPT
		});
		const withNew = await keyedCheck(target, null, null, {
			uri: '/dash',
			cookie: again.cookie,
			accept: JSON_ACCEPT
		});

		expect(again.landedAt).toBe(`${app.address}/dash`);
		expect(withNew.status).toBe(200);
		expect(withOld.headers.get('x-auth-reason')).toBe('no_session');
	});

	it('refuses a sign-in that comes back older than asked, even with the age taken off the request', async () => {
		const target = { slug: w.acme.slug, app };
		setSystemTime(T0);
		const first = await signInThrough(target, w.acme.staffMember);
		setSystemTime(T0 + 20 * 60_000);
		const sent = await keyedCheck(target, null, null, {
			uri: '/dash',
			cookie: first.cookie
		});
		first.jar.absorb(sent);
		const toProject = new URL(sent.headers.get('location') ?? '');
		toProject.searchParams.delete('max_age');

		const step = await first.browser.open(toProject.toString());
		const callback = new URL(step.url);
		const returned = await keyedCheck(target, null, null, {
			uri: `${callback.pathname}${callback.search}`,
			cookie: first.jar.header
		});

		expect(callback.pathname).toBe('/_foxauth/callback');
		expect(returned.status).toBe(403);
		expect(returned.headers.get('x-auth-reason')).toBe('sign_in_not_fresh');
		expect(returned.headers.getSetCookie().join(';')).not.toContain(
			`__Host-foxauth-${app.id}=`
		);
	});
});

/**
 * @proves An app open only in some hours lets people in exactly within them — past midnight included — tells a person
 * turned away when it opens again in its own time zone, and cannot be given hours without saying whose clock they are.
 */
describe('an app open only in some hours', () => {
	let app: AppView;
	/* Fri 22:00–06:00 and Mon–Fri 08:00–20:00, Moscow. */
	const HOURS = {
		kind: 'time',
		windows: [
			{ days: [0, 1, 2, 3, 4], start: 8 * 60, end: 20 * 60 },
			{ days: [4], start: 22 * 60, end: 6 * 60 }
		]
	};
	const moscow = (day: number, hh: number, mm = 0) =>
		Date.UTC(2026, 10, 2 + day, hh - 3, mm);

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		app = await createApp(w.cookie, w.acme.id, { rootGroups: [w.acme.staff] });
		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			{
				timeZone: ZONE,
				rules: [{ path: '/', who: { kind: 'project' }, conditions: [HOURS] }]
			}
		);
		expect(reply.status).toBe(200);
	});

	afterAll(() => {
		setSystemTime();
	});

	it.each([
		['Thursday 14:05', moscow(3, 14, 5), 'no_session'],
		['Thursday 20:00, as the window closes', moscow(3, 20, 0), 'outside_hours'],
		['Saturday 14:05', moscow(5, 14, 5), 'outside_hours'],
		['Saturday 03:00, inside Friday night', moscow(5, 3, 0), 'no_session'],
		['Saturday 06:00, as Friday night ends', moscow(5, 6, 0), 'outside_hours'],
		['Friday 23:30, inside Friday night', moscow(4, 23, 30), 'no_session']
	] as const)('%s is decided as the hours say', async (_moment, at, reason) => {
		setSystemTime(at);

		const response = await keyedCheck({ slug: w.acme.slug, app }, null, null, {
			uri: '/',
			accept: JSON_ACCEPT
		});

		expect(response.headers.get('x-auth-reason')).toBe(reason);
	});

	it('tells a person turned away when it opens again, in its own time zone', async () => {
		setSystemTime(moscow(5, 14, 5));

		const response = await keyedCheck({ slug: w.acme.slug, app }, null, null, {
			uri: '/'
		});
		const page = await response.text();

		expect(response.status).toBe(403);
		expect(page).toContain('Monday');
		expect(page).toContain('08:00');
		expect(page).toContain('Europe/Moscow');
	});

	it.each([
		['no time zone', undefined],
		['a time zone no one knows', 'Mars/Olympus_Mons']
	] as const)('hours with %s are not saved', async (_case, timeZone) => {
		setSystemTime();
		const other = await createApp(w.cookie, w.acme.id, {
			rootGroups: [w.acme.staff]
		});

		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, other.id),
			w.cookie,
			{
				...(timeZone === undefined ? {} : { timeZone }),
				rules: [{ path: '/', who: { kind: 'project' }, conditions: [HOURS] }]
			}
		);

		expect(reply.status).toBe(422);
		expect((reply.body as { field: string }).field).toBe('timeZone');
	});
});

/**
 * @proves An app limited to a department lets in exactly the people whose department an administrator or a directory
 * recorded as one of the values, cannot be limited by something a person writes about themselves at a provider, and
 * cannot be limited to a department nobody has.
 */
describe('an app limited to a department', () => {
	let app: AppView;
	let inOps: Member;
	let noDepartment: Member;
	const OPS_ONLY = {
		kind: 'attribute',
		attribute: 'department',
		values: ['Ops']
	};

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		inOps = await member(w.acme, [w.acme.staff]);
		noDepartment = await member(w.acme, [w.acme.staff]);
		await getUserStore(w.acme.id).update(inOps.accountId, {
			profile: { enterprise: { department: 'Ops' } }
		});
		app = await createApp(w.cookie, w.acme.id, { rootGroups: [w.acme.staff] });
		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			{
				rules: [
					{
						path: '/',
						who: { kind: 'groups', groups: [w.acme.staff] },
						conditions: [OPS_ONLY]
					}
				]
			}
		);
		expect(reply.status).toBe(200);
	});

	it('lets in a person in Ops and refuses one with no department', async () => {
		const target = { slug: w.acme.slug, app };
		const ops = await signInThrough(target, inOps);
		const none = await signInThrough(target, noDepartment);

		const allowed = await keyedCheck(target, null, null, {
			cookie: ops.cookie,
			accept: JSON_ACCEPT
		});
		const refused = await keyedCheck(target, null, null, {
			cookie: none.cookie,
			accept: JSON_ACCEPT
		});

		expect(allowed.status).toBe(200);
		expect(refused.headers.get('x-auth-reason')).toBe('attribute_mismatch');
	});

	it.each(['name', 'given_name', 'family_name', 'picture', 'locale', 'email'])(
		'a condition on the claim %s, which a person can set at their provider, is not accepted',
		async (claim) => {
			const reply = await admin(
				'PATCH',
				behindProxyPath(w.acme.id, app.id),
				w.cookie,
				{
					rules: [
						{
							path: '/',
							who: { kind: 'project' },
							conditions: [
								{
									kind: 'attribute',
									attribute: `claim:${claim}`,
									values: ['x']
								}
							]
						}
					]
				}
			);

			expect(reply.status).toBe(422);
		}
	);

	it('a department nobody in the project has is not saved', async () => {
		const reply = await admin(
			'PATCH',
			behindProxyPath(w.acme.id, app.id),
			w.cookie,
			{
				rules: [
					{
						path: '/',
						who: { kind: 'project' },
						conditions: [
							{ kind: 'attribute', attribute: 'department', values: ['Nobody'] }
						]
					}
				]
			}
		);

		expect(reply.status).toBe(409);
		expect((reply.body as { code: string }).code).toBe(
			'attribute_matches_nobody'
		);
	});

	it('counts the people whose department is one of the values', async () => {
		const reply = await admin(
			'GET',
			`/admin/api/projects/${w.acme.id}/attribute-matches?attribute=department&value=Ops&value=Nobody`,
			w.cookie
		);

		expect(reply.status).toBe(200);
		expect((reply.body as { count: number }).count).toBe(1);
	});
});
