import { describe, it, expect, beforeAll, beforeEach, spyOn } from 'bun:test';
import bootstrap, { agent, getHeader } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import {
	getUserStore,
	getBucketStore,
	getProjectStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { sentEmails, resetSentEmails } from '../mail_capture.ts';

const PASSWORD = 'correct horse battery';

// The wording the login page must show after a registration that needs verification, and the two markers
// that make "notice" and "error" distinguishable in the markup rather than only in prose.
const NOTICE_TEXT = 'Check your inbox';
const NOTICE_MARKER = '#e6f4ff';
const ERROR_MARKER = '#fff2f0';

let verifyBucketId: string;
let closedBucketId: string;
let openBucketId: string;

async function seedBucket(
	name: string,
	clientId: string,
	fields: Record<string, unknown>
): Promise<string> {
	const bucket = await getBucketStore().create({ name, ...fields });
	const project = await getProjectStore().create({
		name,
		slug: `${clientId}-${Math.random()}`
	});
	await getProjectStore().update(project._id, {
		bucketId: bucket._id,
		clientIds: [clientId]
	});
	return bucket._id;
}

// Drive a real authorization request so the provider prompts login and hands back an interaction uid and
// its `_interaction` cookie (the pattern link.spec.ts and reset.spec.ts share).
async function startInteraction(clientId: string) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const location = getHeader(response, 'location');
	const uid = location.split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
}

/*
 * Every page in this suite is fetched through elysia.handle rather than the Eden client: the refusals are
 * non-2xx HTML, for which the client exposes no readable body, and a byte-for-byte comparison of two
 * renders needs the real Response either way.
 */
async function getPage(path: string, cookie?: string) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			headers: cookie ? { cookie } : {}
		})
	);
	return {
		status: res.status,
		text: await res.text(),
		contentType: res.headers.get('content-type') ?? '',
		csp: res.headers.get('content-security-policy')
	};
}

async function postForm(
	path: string,
	cookie: string,
	fields: Record<string, string>
) {
	const res = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				cookie
			},
			body: new URLSearchParams(fields).toString()
		})
	);
	return {
		status: res.status,
		text: await res.text(),
		contentType: res.headers.get('content-type') ?? '',
		csp: res.headers.get('content-security-policy'),
		location: res.headers.get('location')
	};
}

async function register(clientId: string, email: string, password = PASSWORD) {
	const { uid, cookie } = await startInteraction(clientId);
	const { response } = await agent
		.ui({ uid })
		.registration.post(
			{ email, password, confirmPassword: password },
			{ headers: { cookie } }
		);
	return { uid, cookie, response };
}

describe('interaction UI — the post-registration notice (US1)', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'pages' });
		resetAdminMemoryStores();
		verifyBucketId = await seedBucket('UI Verify Bucket', 'ui-verify-app', {
			emailVerificationRequired: true,
			verificationMethod: 'link'
		});
		closedBucketId = await seedBucket('UI Closed Bucket', 'ui-closed-app', {
			registrationOpen: false
		});
		openBucketId = await seedBucket('UI Open Bucket', 'ui-open-app', {
			emailVerificationRequired: false
		});
	});

	beforeEach(() => {
		resetSentEmails();
	});

	it('sends the registrant to a login page that tells them to check their inbox', async () => {
		const email = 'notice-one@x.io';
		const { uid, cookie, response } = await register('ui-verify-app', email);

		expect(response.status).toBe(303);
		expect(getHeader(response, 'location')).toContain(
			`/ui/${uid}/login?notice=verify`
		);
		expect(sentEmails.length).toBe(1);

		const page = await getPage(`/ui/${uid}/login?notice=verify`, cookie);
		expect(page.status).toBe(200);
		expect(page.text).toContain(NOTICE_TEXT);
	});

	it('says nothing when the bucket does not require verification', async () => {
		const email = 'notice-two@x.io';
		const { uid, cookie, response } = await register('ui-open-app', email);

		expect(response.status).toBe(303);
		expect(getHeader(response, 'location')).toBe(`/ui/${uid}/login`);
		expect(sentEmails.length).toBe(0);

		const page = await getPage(`/ui/${uid}/login`, cookie);
		expect(page.status).toBe(200);
		expect(page.text).not.toContain(NOTICE_TEXT);
		expect(page.text).not.toContain(NOTICE_MARKER);
	});

	it('ignores a notice it did not mint, whatever the value looks like', async () => {
		const { uid, cookie } = await startInteraction('ui-verify-app');
		const plain = await getPage(`/ui/${uid}/login`, cookie);

		const crafted = [
			'?notice=nonsense',
			'?notice=',
			'?notice=verify_',
			'?notice=VERIFY',
			'?notice=a&notice=b',
			`?notice=${encodeURIComponent('<script>alert(1)</script>')}`
		];

		for (const query of crafted) {
			const page = await getPage(`/ui/${uid}/login${query}`, cookie);
			// Byte-identical to the no-notice render: an unrecognised identifier is not a near miss, and
			// nothing from the request is rendered.
			expect(page.status).toBe(200);
			expect(page.text).toBe(plain.text);
			expect(page.text).not.toContain('nonsense');
			expect(page.text).not.toContain('alert(1)');
			expect(page.text).not.toContain(NOTICE_MARKER);
		}
	});

	it('shows the error and not a stale notice when a submission is rejected', async () => {
		const { uid, cookie } = await startInteraction('ui-verify-app');

		const rejected = await postForm(`/ui/${uid}/login`, cookie, {
			username: 'nobody@x.io',
			password: 'whatever'
		});

		expect(rejected.status).toBe(400);
		expect(rejected.text).toContain('Invalid username or password');
		expect(rejected.text).not.toContain(NOTICE_TEXT);
		expect(rejected.text).not.toContain(NOTICE_MARKER);
	});

	it('renders a notice and an error as visibly different things', async () => {
		const { uid, cookie } = await startInteraction('ui-verify-app');

		const notice = await getPage(`/ui/${uid}/login?notice=verify`, cookie);
		const error = await postForm(`/ui/${uid}/login`, cookie, {
			username: 'nobody@x.io',
			password: 'whatever'
		});

		expect(notice.text).toContain(NOTICE_MARKER);
		expect(notice.text).not.toContain(ERROR_MARKER);
		expect(error.text).toContain(ERROR_MARKER);
		expect(error.text).not.toContain(NOTICE_MARKER);
	});

	it('carries the notice in the hydration props, so the browser does not erase it', async () => {
		const { uid, cookie } = await startInteraction('ui-verify-app');
		const page = await getPage(`/ui/${uid}/login?notice=verify`, cookie);

		expect(page.text).toContain('window.PROPS=');
		expect(page.text).toContain(NOTICE_TEXT);
		// The props script must carry the message too — the hydrated tree is built from it.
		const props = page.text.match(/window\.PROPS=(\{.*?\})<\/script>/)?.[1];
		expect(props).toBeDefined();
		expect(JSON.parse(props!).notice).toContain(NOTICE_TEXT);
	});
});

describe('interaction UI — registration refusals (US2)', () => {
	beforeEach(() => {
		resetSentEmails();
	});

	it('refuses a submission to a closed bucket with a rendered page, not a bare body', async () => {
		const email = 'closed-one@x.io';
		const { uid, cookie } = await startInteraction('ui-closed-app');

		const res = await elysia.handle(
			new Request(`http://e.ly/ui/${uid}/registration`, {
				method: 'POST',
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
					cookie
				},
				body: new URLSearchParams({
					email,
					password: PASSWORD,
					confirmPassword: PASSWORD
				}).toString()
			})
		);
		const text = await res.text();

		// The status is what it always was; only the body changes.
		expect(res.status).toBe(403);
		expect(res.headers.get('content-type')).toContain('text/html');
		expect(res.headers.get('content-security-policy')).toBeTruthy();
		expect(text).toContain('not accepting new accounts');
		expect(await getUserStore(closedBucketId).findByEmail(email)).toBeNull();
		expect(sentEmails.length).toBe(0);
	});

	it('refuses the registration form itself for a closed bucket', async () => {
		const { uid, cookie } = await startInteraction('ui-closed-app');
		const form = await getPage(`/ui/${uid}/registration`, cookie);

		expect(form.status).toBe(403);
		expect(form.text).toContain('not accepting new accounts');
		// Not a form that cannot succeed.
		expect(form.text).not.toContain('name="confirmPassword"');
	});

	it('re-renders the form on a mismatch, keeping the address and neither password', async () => {
		const email = 'mismatch@x.io';
		const { uid, cookie } = await startInteraction('ui-open-app');

		const res = await postForm(`/ui/${uid}/registration`, cookie, {
			email,
			password: PASSWORD,
			confirmPassword: 'something else'
		});

		expect(res.status).toBe(400);
		expect(res.text).toContain('Passwords do not match');
		/*
		 * The address must be in the *field*, not merely somewhere in the document — the props script
		 * carries it too, and a body-wide `toContain` would pass on an empty form.
		 */
		expect(res.text).toMatch(
			new RegExp(`<input[^>]*name="email"[^>]*value="${email}"`)
		);
		expect(res.text).toContain('name="confirmPassword"');
		expect(res.text).not.toContain(PASSWORD);
		expect(res.text).not.toContain('something else');
		expect(await getUserStore(openBucketId).findByEmail(email)).toBeNull();
	});

	it('carries the mismatch error and the address in the hydration props', async () => {
		const email = 'mismatch-props@x.io';
		const { uid, cookie } = await startInteraction('ui-open-app');

		const res = await postForm(`/ui/${uid}/registration`, cookie, {
			email,
			password: PASSWORD,
			confirmPassword: 'no'
		});

		const props = res.text.match(/window\.PROPS=(\{.*?\})<\/script>/)?.[1];
		expect(props).toBeDefined();
		const parsed = JSON.parse(props!);
		expect(parsed.errorMessage).toContain('Passwords do not match');
		expect(parsed.email).toBe(email);
		expect(JSON.stringify(parsed)).not.toContain(PASSWORD);
	});

	it('leaves no unsubstituted props placeholder on any registration response', async () => {
		const { uid, cookie } = await startInteraction('ui-open-app');
		const form = await getPage(`/ui/${uid}/registration`, cookie);

		expect(form.status).toBe(200);
		expect(form.text).not.toContain('<!--app-props-->');
		expect(form.text).toContain('window.PROPS=');
	});

	it('reports a failed verification send on a rendered page, account intact', async () => {
		const email = 'send-fail@x.io';
		const push = spyOn(sentEmails, 'push').mockImplementation(() => {
			throw new Error('smtp refused the message');
		});

		try {
			const { uid, cookie } = await startInteraction('ui-verify-app');
			const res = await postForm(`/ui/${uid}/registration`, cookie, {
				email,
				password: PASSWORD,
				confirmPassword: PASSWORD
			});

			expect(res.status).toBe(502);
			// A rendered page, not the bare body it used to be: the status was already 502.
			expect(res.contentType).toContain('text/html');
			expect(res.csp).toBeTruthy();
			expect(res.text).toContain('<!doctype html>');
			expect(res.text).toContain('could not send');
		} finally {
			push.mockRestore();
		}

		// The account was created and is unverified: the page changes what the user reads, not the store.
		const user = await getUserStore(verifyBucketId).findByEmail(email);
		expect(user).not.toBeNull();
		expect(user?.verified).toBe(false);
	});

	it('offers no control that cannot work, and keeps the ones that can (US4)', async () => {
		const { uid, cookie } = await startInteraction('ui-open-app');
		const login = await getPage(`/ui/${uid}/login`, cookie);

		// Nothing federated: neither the label nor the icon a stripped-down button would still carry.
		expect(login.text).not.toContain('Sign in with Google');
		expect(login.text).not.toContain('anticon-google');
		expect(login.text).not.toContain('data-icon="google"');

		// Everything that remains does something.
		expect(login.text).toContain('name="username"');
		expect(login.text).toContain('name="password"');
		expect(login.text).toContain('name="remember"');
		expect(login.text).toContain(`/ui/${uid}/registration`);
		expect(login.text).toContain(`/ui/${uid}/forgot-password`);
	});

	it('stays non-committal about an address that already exists', async () => {
		const email = 'existing@x.io';
		const first = await register('ui-open-app', email);
		expect(first.response.status).toBe(303);

		const { uid, cookie } = await startInteraction('ui-open-app');
		const second = await elysia.handle(
			new Request(`http://e.ly/ui/${uid}/registration`, {
				method: 'POST',
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
					cookie
				},
				body: new URLSearchParams({
					email,
					password: PASSWORD,
					confirmPassword: PASSWORD
				}).toString()
			})
		);

		// Byte-for-byte the accepted outcome: same status, same target, no page of its own.
		expect(second.status).toBe(303);
		expect(second.headers.get('location')).toBe(`/ui/${uid}/login`);
		expect(await second.text()).toBe('');
	});
});
