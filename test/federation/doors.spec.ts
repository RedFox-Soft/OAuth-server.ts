import {
	describe,
	it,
	expect,
	beforeAll,
	beforeEach,
	afterEach
} from 'bun:test';

import bootstrap from '../test_helper.ts';
import {
	getBucketStore,
	getUserStore,
	resetAdminMemoryStores
} from 'lib/adapters/index.ts';
import { elysia } from 'lib/index.ts';
import { mock } from '../fetch_mock.ts';
import { idpStub } from './idp_stub.ts';
import {
	expectRefusalPage,
	get,
	provider,
	seedBucket,
	walk
} from './harness.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { agent, getHeader } from '../test_helper.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';

/*
 * A bucket that only accepts federated sign-in.
 *
 * `passwordLogin: false` is one setting with five consequences, and each is a door that would otherwise be
 * an invitation to a dead end: the sign-in POST, both registration methods and both forgot-password methods.
 * The login page stops offering any of them, and the routes refuse rather than merely being unlinked —
 * because a URL nobody links to is still a URL anybody can type.
 */

const FEDERATED = 'doors-federated-app';
const PASSWORD = 'doors-password-app';

async function startInteractionFor(clientId: string) {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid'
	});
	const { response } = await agent.auth.get({ query: auth.params });
	const uid = getHeader(response, 'location').split('/')[2];
	const cookie = response.headers.get('set-cookie');
	if (!cookie) throw new Error('expected an interaction cookie from /auth');
	return { uid, cookie };
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
				cookie,
				'content-type': 'application/x-www-form-urlencoded'
			},
			body: new URLSearchParams(fields).toString()
		})
	);
	return {
		status: res.status,
		text: await res.text(),
		contentType: res.headers.get('content-type') ?? '',
		csp: res.headers.get('content-security-policy'),
		location: res.headers.get('location') ?? ''
	};
}

describe('a bucket that only accepts federated sign-in', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'doors' });
	});

	beforeEach(() => {
		resetAdminMemoryStores();
	});

	afterEach(() => {
		mock.restore();
	});

	it('offers no password form and no password links on its login page', async () => {
		const idp = await idpStub('https://idp-doors-page.test');
		await seedBucket(FEDERATED, {
			passwordLogin: false,
			federation: [provider(idp.origin, { emailTrusted: true })]
		});
		const { uid, cookie } = await startInteractionFor(FEDERATED);

		const page = await get(`/ui/${uid}/login`, cookie);

		expect(page.status).toBe(200);
		// The provider is the only way in, and it is offered.
		expect(page.text).toContain(`/ui/${uid}/federation/acme-sso/start`);

		// Every password affordance is gone — from the markup...
		expect(page.text).not.toContain('name="password"');
		expect(page.text).not.toContain('name="username"');
		expect(page.text).not.toContain(`/ui/${uid}/registration`);
		expect(page.text).not.toContain(`/ui/${uid}/forgot-password`);
		expect(page.text).not.toContain('Remember me');
		/*
		 * ...and from the props, which is the half that fails in a browser only. A page whose props still said
		 * `passwordLogin: true` would render correctly and then grow a password form on hydration.
		 */
		expect(page.text).toContain('"passwordLogin":false');
	});

	it('refuses all five password-only routes', async () => {
		const idp = await idpStub('https://idp-doors-routes.test');
		await seedBucket(FEDERATED, {
			passwordLogin: false,
			federation: [provider(idp.origin, { emailTrusted: true })]
		});
		const { uid, cookie } = await startInteractionFor(FEDERATED);

		const submitted = await postForm(`/ui/${uid}/login`, cookie, {
			username: 'someone@acme.test',
			password: 'whatever'
		});
		expect(submitted.status).toBe(403);

		const registrationForm = await get(`/ui/${uid}/registration`, cookie);
		expectRefusalPage(registrationForm, 403);

		const registered = await postForm(`/ui/${uid}/registration`, cookie, {
			email: 'new@acme.test',
			password: 'a-long-password',
			confirmPassword: 'a-long-password'
		});
		expect(registered.status).toBe(403);

		const forgotForm = await get(`/ui/${uid}/forgot-password`, cookie);
		expectRefusalPage(forgotForm, 403);

		const forgotSubmitted = await postForm(
			`/ui/${uid}/forgot-password`,
			cookie,
			{ email: 'someone@acme.test' }
		);
		expect(forgotSubmitted.status).toBe(403);
	});

	it('refuses the password sign-in before deciding anything about the address', async () => {
		const idp = await idpStub('https://idp-doors-noprobe.test');
		const bucketId = await seedBucket(FEDERATED, {
			passwordLogin: false,
			federation: [provider(idp.origin, { emailTrusted: true })]
		});
		const store = getUserStore(bucketId);
		await store.create(
			'real@acme.test',
			await Bun.password.hash('correct'),
			[],
			true
		);
		const { uid, cookie } = await startInteractionFor(FEDERATED);

		/*
		 * A real address with the right password, and an address that does not exist, answer identically.
		 * The door is closed before any lookup, so this surface cannot be used to probe membership — and the
		 * refusal reveals a bucket setting rather than anything about an account.
		 */
		const real = await postForm(`/ui/${uid}/login`, cookie, {
			username: 'real@acme.test',
			password: 'correct'
		});
		const fake = await postForm(`/ui/${uid}/login`, cookie, {
			username: 'nobody@acme.test',
			password: 'correct'
		});

		expect(real.status).toBe(403);
		expect(fake.status).toBe(403);
		expect(real.text).toBe(fake.text);
	});

	it('still signs in through the provider', async () => {
		const idp = await idpStub('https://idp-doors-works.test');
		const bucketId = await seedBucket(FEDERATED, {
			passwordLogin: false,
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteractionFor(FEDERATED);
		const { complete } = await walk(uid, cookie, {
			idp,
			claims: { email: 'only-way-in@acme.test', email_verified: true }
		});

		expect(complete?.status).toBe(303);
		expect(await getUserStore(bucketId).list()).toHaveLength(1);
	});

	it('leaves a bucket that keeps password login exactly as it was', async () => {
		await seedBucket(PASSWORD, {});
		const { uid, cookie } = await startInteractionFor(PASSWORD);

		const page = await get(`/ui/${uid}/login`, cookie);
		expect(page.text).toContain('name="password"');
		expect(page.text).toContain(`/ui/${uid}/registration`);
		// Defaulted, not merely absent: a bucket written before this field existed keeps its password door.
		expect(page.text).toContain('"passwordLogin":true');

		const forgot = await get(`/ui/${uid}/forgot-password`, cookie);
		expect(forgot.status).toBe(200);
	});

	it('reads back password login as available for a bucket stored without the field', async () => {
		const bucket = await getBucketStore().create({
			ownerGroupId: UNASSIGNED_GROUP_ID,
			name: 'legacy'
		});
		// The store defaults it on read as well as on create, because `undefined` is falsy and would have
		// closed the password door on every bucket that predates the field.
		expect(bucket.passwordLogin).toBe(true);
		expect((await getBucketStore().find(bucket._id))?.passwordLogin).toBe(true);
	});

	it('keeps federated provisioning independent of password registration', async () => {
		const idp = await idpStub('https://idp-doors-indep.test');
		const bucketId = await seedBucket(FEDERATED, {
			// Password sign-ups closed, federated provisioning open: the two settings are unrelated, which is
			// the arrangement an enterprise actually asks for.
			registrationOpen: false,
			federation: [provider(idp.origin, { emailTrusted: true })]
		});

		idp.expectDiscovery();
		const { uid, cookie } = await startInteractionFor(FEDERATED);
		const { complete } = await walk(uid, cookie, {
			idp,
			claims: { email: 'jit-despite-closed@acme.test', email_verified: true }
		});

		expect(complete?.status).toBe(303);
		expect(await getUserStore(bucketId).list()).toHaveLength(1);

		/*
		 * And the password registration form is still closed, as that bucket setting says. A fresh
		 * interaction, because the one above was consumed by completing the sign-in — reusing it would be
		 * refused for having no interaction rather than for the reason under test.
		 */
		const next = await startInteractionFor(FEDERATED);
		const form = await get(`/ui/${next.uid}/registration`, next.cookie);
		expect(form.status).toBe(403);
	});
});
