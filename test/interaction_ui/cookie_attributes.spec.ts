import { describe, it, expect, beforeAll } from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getBucketStore,
	getProjectStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { ttl } from 'lib/configs/liveTime.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

const CLIENT_ID = 'ui-open-app';
const PASSWORD = 'correct horse battery';

/*
 * Asserted on the response header rather than on a cookie string threaded through by hand: a
 * hand-driven cookie string is not a cookie jar, so it cannot observe a `Set-Cookie` whose attributes
 * fail to apply — the blindness wiki/concepts/cookie-path-scoping.md names as the reason every
 * existing suite passed while the browser kept the wrong cookie.
 */
function setCookieFor(response: Response, name: string): string {
	const all = response.headers.getSetCookie();
	const found = all.find((c) => c.startsWith(`${name}=`));
	if (!found) {
		throw new Error(
			`expected a ${name} Set-Cookie, got ${JSON.stringify(all)}`
		);
	}
	return found;
}

// `Secure` is the attribute this suite exists for; the other two travel with it from one owner
// (endUserCookieAttributes) and would regress the same way.
function expectHardened(header: string) {
	expect(header).toContain('HttpOnly');
	expect(header).toContain('Secure');
	expect(header).toContain('SameSite=Strict');
}

// The `name=value` pair only, for re-sending as a request cookie.
function pairOf(header: string): string {
	return header.split(';')[0];
}

async function startInteraction() {
	const auth = new AuthorizationRequest({
		client_id: CLIENT_ID,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const location = getHeader(response, 'location');
	return { uid: location.split('/')[2], response };
}

/*
 * Registration, then password login: the login POST is where the *authenticated* `_session` is first
 * written, and it is written through the `/ui` cookie schema rather than the authorization routes' one.
 */
async function loginNewUser(email: string) {
	const started = await startInteraction();
	const interactionCookie = pairOf(
		setCookieFor(started.response, '_interaction')
	);

	const registered = await agent
		.ui({ uid: started.uid })
		.registration.post(
			{ email, password: PASSWORD, confirmPassword: PASSWORD },
			{ headers: { cookie: interactionCookie } }
		);
	expect(registered.response.status).toBe(303);

	const loggedIn = await agent
		.ui({ uid: started.uid })
		.login.post(
			{ username: email, password: PASSWORD },
			{ headers: { cookie: interactionCookie } }
		);
	expect(loggedIn.response.status).toBe(303);
	return { started, response: loggedIn.response };
}

describe('end-user cookie attributes', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'pages' });
		resetAdminMemoryStores();
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Cookie Attributes Bucket',
			emailVerificationRequired: false
		});
		const project = await getProjectStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'Cookie Attributes',
			slug: `cookie-attrs-${Math.random()}`
		});
		await getProjectStore().update(project._id, {
			bucketId: bucket._id,
			clientIds: [CLIENT_ID]
		});
	});

	it('writes the interaction cookie hardened, path-scoped, and expiring with the interaction', async () => {
		const { uid, response } = await startInteraction();
		const header = setCookieFor(response, '_interaction');

		expectHardened(header);
		expect(header).toContain(`Path=/ui/${uid}`);
		// Seconds, not milliseconds: `ttl.Interaction * 1000` gave the cookie a ~41-day lifetime.
		expect(header).toContain(`Max-Age=${ttl.Interaction}`);
	});

	it('writes the authenticated session cookie hardened from the /ui login POST', async () => {
		// The regression: the `/ui` guard declared no cookie options, so this response carried
		// `_session` with no HttpOnly, no SameSite and no Secure at all.
		const { response } = await loginNewUser('cookie-attrs-login@x.io');
		const header = setCookieFor(response, '_session');

		expectHardened(header);
		expect(header).toContain('Path=/');
	});

	it('clears the interaction cookie at the path it was written with', async () => {
		const { response } = await loginNewUser('cookie-attrs-consent@x.io');
		// Login resolved into a consent prompt, which is a new interaction under a new uid — so it is
		// this response that carries the live cookie, and the consent POST below that clears it.
		const consentUid = getHeader(response, 'location').split('/')[2];
		const cookie = [
			pairOf(setCookieFor(response, '_session')),
			pairOf(setCookieFor(response, '_interaction'))
		].join('; ');

		const { response: allowed } = await agent
			.ui({ uid: consentUid })
			.consent.post({ action: 'allow' }, { headers: { cookie } });
		expect(allowed.status).toBe(303);

		const header = setCookieFor(allowed, '_interaction');
		expect(header).toContain('Max-Age=0');
		// `remove()` emitted `Path=/` here, which is a different cookie than the one at /ui/<uid> —
		// so the interaction cookie was never actually cleared in a browser.
		expect(header).toContain(`Path=/ui/${consentUid}`);
		expectHardened(header);
	});

	/*
	 * Not asserted as a *clear*: the confirm handler sets `expiredSessionCookie()` on a full sign-out and
	 * then runs `setCookies()` unconditionally, which re-issues the cookie (for the just-destroyed
	 * session record) and overwrites it. That predates this change and the end_session suite encodes the
	 * re-issue, so what is asserted here is the attribute set every write of `_session` must carry. The
	 * clearing attributes themselves are covered where they do reach the wire: the admin console's
	 * sign-out, in test/admin/login_flow.spec.ts.
	 */
	it('writes the session cookie hardened from the end-session confirm response', async () => {
		const { response } = await loginNewUser('cookie-attrs-logout@x.io');
		let sessionCookie = pairOf(setCookieFor(response, '_session'));

		const page = await agent.logout.get({
			query: {},
			headers: { cookie: sessionCookie, accept: 'text/html' }
		});
		expect(page.response.status).toBe(200);
		sessionCookie = pairOf(setCookieFor(page.response, '_session'));
		const xsrf =
			/name="xsrf"[^>]*value="([^"]+)"|value="([^"]+)"[^>]*name="xsrf"/.exec(
				(page.data as string) ?? ''
			);
		const secret = xsrf?.[1] ?? xsrf?.[2];
		expect(secret).toBeTruthy();

		const { response: confirmed } = await agent.logout.confirm.post(
			{ xsrf: secret as string, logout: 'true' },
			{ headers: { cookie: sessionCookie, accept: 'text/html' } }
		);

		const header = setCookieFor(confirmed, '_session');
		expect(header).toContain('Path=/');
		expectHardened(header);
	});
});
