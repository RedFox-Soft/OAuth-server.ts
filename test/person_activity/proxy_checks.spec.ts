import {
	afterEach,
	beforeAll,
	describe,
	expect,
	it,
	setSystemTime
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import { admin } from '../provisioning/helpers.ts';
import {
	behindProxyPath,
	checkApp,
	createApp,
	expectStatus,
	signInThrough,
	world,
	type AppView,
	type World
} from '../behind_proxy/helpers.ts';
import {
	fromProxy,
	issueProxyKey
} from '../behind_proxy/conditions_helpers.ts';
import { activityOf, from, only } from './helpers.ts';

let w: World;
let app: AppView;

/*
 * Staff open the app; `/admin` is for Admins only; `/reports` asks for a sign-in within the last 15 minutes. Set on
 * one app per case, so a case never meets another's sessions.
 */
async function wiki(): Promise<AppView> {
	const created = await createApp(w.cookie, w.acme.id, {
		rootGroups: [w.acme.staff],
		name: 'Wiki'
	});
	const reply = await admin(
		'PATCH',
		behindProxyPath(w.acme.id, created.id),
		w.cookie,
		{
			rules: [
				{ path: '/', who: { kind: 'groups', groups: [w.acme.staff] } },
				{ path: '/admin', who: { kind: 'groups', groups: [w.acme.admins] } },
				{
					path: '/reports',
					who: { kind: 'groups', groups: [w.acme.staff] },
					conditions: [{ kind: 'fresh', maxAgeMinutes: 15 }]
				}
			]
		}
	);
	expectStatus(reply, 200, 'setting the wiki rules');
	return created;
}

function target() {
	return { slug: w.acme.slug, app };
}

async function appRows(accountId: string) {
	const page = await activityOf(w.cookie, w.acme.id, accountId, {
		kind: 'app'
	});
	/* What the person used is spec 134's (use.spec.ts); these cases are about refusals and asks. */
	return page.rows.filter(
		(row) => row.place.appId === app.id && row.outcome !== 'let_in'
	);
}

/**
 * @proves What an app behind the proxy asked of a person or refused them is kept on their activity, with the rule's
 * path as configured, the reason in words and the app to check against today's rules; a check with no person keeps
 * nothing.
 */
describe('a person at an app behind the proxy', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		from('203.0.113.9');
	});

	afterEach(() => {
		setSystemTime();
	});

	it("shows a refusal with the rule's path and a check link", async () => {
		app = await wiki();
		const signed = await signInThrough(target(), w.acme.staffMember);
		const refused = await checkApp(target(), {
			uri: '/admin/users',
			cookie: signed.cookie
		});
		expect(refused.status).toBe(403);

		const row = only(await appRows(w.acme.staffMember.accountId), 'app row');
		expect({
			outcome: row.words.outcome,
			reason: row.words.reason,
			place: row.place.name,
			check: row.check,
			address: row.address
		}).toEqual({
			outcome: 'Refused',
			reason: 'Not in the groups that may open /admin',
			place: 'Wiki',
			check: { app: app.id },
			address: null
		});
	});

	it('shows an app asking a person to sign in again with the freshness reason', async () => {
		app = await wiki();
		const signed = await signInThrough(target(), w.acme.staffMember);
		setSystemTime(new Date(Date.now() + 20 * 60 * 1000));
		const asked = await checkApp(target(), {
			uri: '/reports/q3',
			cookie: signed.cookie
		});
		expect(asked.headers.get('x-auth-reason')).toBe('sign_in_again');

		const row = only(await appRows(w.acme.staffMember.accountId), 'app row');
		expect([row.words.outcome, row.words.reason]).toEqual([
			'Asked to sign in again',
			'Signed in too long ago for /reports'
		]);
	});

	it('names the app a sign-in through the proxy was for', async () => {
		app = await wiki();
		await signInThrough(target(), w.acme.adminMember);

		const page = await activityOf(
			w.cookie,
			w.acme.id,
			w.acme.adminMember.accountId,
			{
				kind: 'signIn',
				outcome: 'let_in'
			}
		);
		expect(page.rows.map((row) => row.place.name)).toContain('Wiki');
	});

	it('records nothing for a check with no person', async () => {
		app = await wiki();
		const anonymous = await checkApp(target(), { uri: '/admin' });
		expect(anonymous.status).toBe(302);

		for (const member of [
			w.acme.staffMember,
			w.acme.adminMember,
			w.acme.outsider
		]) {
			expect(await appRows(member.accountId)).toEqual([]);
		}
	});
});

/**
 * @proves A person's address at the proxy is kept only when the proxy proved, with the project's proxy key, that it
 * passes it; otherwise the row carries no address, whatever the proxy wrote.
 */
describe("a person's address at an app behind the proxy", () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url);
		w = await world();
		from('203.0.113.9');
	});

	it('records a proven proxy address on an app refusal', async () => {
		app = await wiki();
		const key = await issueProxyKey(w.cookie, w.acme.id);
		const headers = fromProxy(key.key, '198.51.100.20');
		const signed = await signInThrough(target(), w.acme.staffMember, {
			headers
		});
		await checkApp(target(), { uri: '/admin', cookie: signed.cookie, headers });

		const row = only(await appRows(w.acme.staffMember.accountId), 'app row');
		expect([row.address, row.addressFrom]).toEqual(['198.51.100.20', 'proxy']);
	});

	it('never records an address the proxy did not prove', async () => {
		app = await wiki();
		const headers = fromProxy(null, '198.51.100.20');
		const signed = await signInThrough(target(), w.acme.staffMember, {
			headers
		});
		await checkApp(target(), { uri: '/admin', cookie: signed.cookie, headers });

		const row = only(await appRows(w.acme.staffMember.accountId), 'app row');
		expect(row.address).toBeNull();
	});
});
