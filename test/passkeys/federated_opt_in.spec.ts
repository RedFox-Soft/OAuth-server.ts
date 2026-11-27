import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { ensureAdminSeed } from 'lib/admin/seed.ts';
import {
	getBucketStore,
	getPasskeyStore,
	getProvisioningConnectionStore,
	getUserStore
} from 'lib/adapters/index.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';
import { createAdminSession } from 'lib/admin/auth/session.ts';
import { configuration } from 'lib/configs/application.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { decideFederatedAccount } from 'lib/federation/resolve.ts';
import { createAdministrator } from '../administrators.ts';
import { present, shaped } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	Browser,
	creationOptionsIn,
	linkIn,
	mailOn,
	person,
	project,
	securityPage,
	seedPasskey,
	xsrfFrom,
	type Project
} from './helpers.ts';
import { Session } from 'lib/models/session.ts';
import { sessionCookieName } from 'lib/consts/param_list.ts';

async function adminReq(
	method: string,
	path: string,
	cookie: string,
	body?: Record<string, unknown>
): Promise<{ status: number; body: Record<string, unknown> }> {
	const response = await elysia.handle(
		new Request(`http://e.ly${path}`, {
			method,
			headers: {
				...(body === undefined ? {} : { 'content-type': 'application/json' }),
				cookie
			},
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		body: text
			? shaped(Type.Record(Type.String(), Type.Unknown()), JSON.parse(text))
			: {}
	};
}

/**
 * @proves Opt-in passkeys for provider-only users (Spec 145 US5), bidirectional SCIM guard, passwordless
 * `/account/security` hiding Two-step verification (FR-023), and closing S10 Attack C in `resolveFederatedUser`.
 */
describe('passkeyForFederated, passwordless account page, and S10 Attack C', () => {
	let acme: Project;
	let superCookie: string;

	beforeAll(async () => {
		await bootstrap(import.meta.url);
		await ensureAdminSeed();
		acme = await project(ACME);
		await getBucketStore().update(acme.bucketId, {
			displayName: 'Acme',
			federation: [
				{
					id: 'corp-sso',
					displayName: 'Corp SSO',
					issuer: 'https://sso.corp.test',
					clientId: 'cid',
					clientSecret: 'csec',
					scopes: ['openid', 'email'],
					emailClaim: 'email',
					emailTrusted: true,
					allowedEmailDomains: [],
					enabled: true,
					provisioning: 'jit'
				}
			]
		});
		const admin = await createAdministrator(
			'super',
			`fed-pk-admin-${Math.random()}@x.io`
		);
		const session = await createAdminSession({
			userId: admin._id,
			bucketId: ADMIN_BUCKET_ID,
			signedInWith: null,
			signInAcr: configuration.acrMap.password,
			signInAmr: ['pwd'],
			signInAt: epochTime(),
			tokens: { accessToken: 'tok' }
		});
		superCookie = `${ADMIN_SESSION_COOKIE}=${session._id}`;
	});

	beforeEach(async () => {
		resetSentEmails();
		await mailOn();
		const conns = await getProvisioningConnectionStore().listByBucket(
			acme.bucketId
		);
		for (const c of conns) {
			await getProvisioningConnectionStore().destroy(c._id);
		}
		await getBucketStore().update(acme.bucketId, {
			passwordLogin: true,
			passkeyLogin: true,
			passkeyForFederated: false
		});
	});

	it('enforces bidirectional SCIM <-> passkeyForFederated conflict guard', async () => {
		// Enable passkeyForFederated when no SCIM exists
		const on = await adminReq(
			'PATCH',
			`/admin/api/projects/${acme.bucketId}`,
			superCookie,
			{ passkeyForFederated: true }
		);
		expect(on.status).toBe(200);

		// Creating a SCIM connection while passkeyForFederated is on -> 409
		const scimBlocked = await adminReq(
			'POST',
			`/admin/api/projects/${acme.bucketId}/provisioning-connections`,
			superCookie,
			{
				displayName: 'Okta',
				providerId: 'corp-sso',
				correlation: { claim: 'email', attribute: 'userName' }
			}
		);
		expect(scimBlocked.status).toBe(409);

		// Turn passkeyForFederated off, add SCIM, then turning passkeyForFederated on -> 409
		await adminReq(
			'PATCH',
			`/admin/api/projects/${acme.bucketId}`,
			superCookie,
			{
				passkeyForFederated: false
			}
		);
		await getProvisioningConnectionStore().create({
			_id: `conn-${Math.random().toString(36).slice(2, 8)}`,
			bucketId: acme.bucketId,
			displayName: 'Okta',
			providerId: 'corp-sso',
			correlation: { claim: 'email', attribute: 'userName' },
			emailTrust: 'trusted',
			oauthCredential: null,
			enabled: true
		});
		const blockedAgain = await adminReq(
			'PATCH',
			`/admin/api/projects/${acme.bucketId}`,
			superCookie,
			{ passkeyForFederated: true }
		);
		expect(blockedAgain.status).toBe(409);
		expect(blockedAgain.body.field).toBe('passkeyForFederated');
	});

	it('lets a provider-only user add a passkey via fresh sign-in + emailed link when passkeyForFederated is on', async () => {
		const who = await person(acme.bucketId);
		await getUserStore(acme.bucketId).update(who.accountId, {
			passwordSet: false,
			federated: [
				{ providerId: 'corp-sso', sub: 'sub-1', linkedAt: new Date() }
			]
		});
		const bucket = present(
			await getBucketStore().find(acme.bucketId),
			'acme bucket'
		);
		const sess = new Session({
			accountId: who.accountId,
			bucketId: acme.bucketId,
			loginTs: epochTime(),
			amr: [],
			acr: configuration.acrMap.federated
		});
		const cookieVal = await sess.save(3600);
		const cookieHeader = `${sessionCookieName(bucket)}=${cookieVal}`;
		const browser = new Browser(acme.origin);

		// Default off -> providerOnly view, no Add button
		const offPage = await browser.request(securityPage(acme), {
			headers: { cookie: cookieHeader }
		});
		expect(await offPage.text()).not.toContain('passkey_start');

		// Turn passkeyForFederated on -> Add button appears
		await getBucketStore().update(acme.bucketId, { passkeyForFederated: true });
		const onPage = await browser.request(securityPage(acme), {
			headers: { cookie: cookieHeader }
		});
		const onHtml = await onPage.text();
		expect(onHtml).toContain('passkey_start');

		// Start passkey add -> mails browser-bound proof link
		const started = await browser.post(
			securityPage(acme),
			{
				action: 'passkey_start',
				xsrf: xsrfFrom(onHtml)
			},
			{ cookie: cookieHeader }
		);
		expect(started.status).toBe(303);
		expect(started.headers.get('location')).toContain('sent=passkey');

		const verifyUrl = new URL(linkIn(who.email, '/account/security/link'));
		const followed = await browser.request(
			`${verifyUrl.pathname}${verifyUrl.search}`,
			{ headers: { cookie: cookieHeader } }
		);
		expect(followed.status).toBe(303);

		const readyPage = await browser.request(securityPage(acme), {
			headers: { cookie: cookieHeader }
		});
		const readyHtml = await readyPage.text();
		const options = creationOptionsIn(readyHtml);
		const device = new SoftAuthenticator();
		const credential = await device.create(options, { origin: acme.origin });
		const added = await browser.post(
			securityPage(acme),
			{
				action: 'passkey_add',
				xsrf: xsrfFrom(readyHtml),
				credential: JSON.stringify(credential)
			},
			{ cookie: cookieHeader }
		);
		expect(added.status).toBe(303);
		expect(added.headers.get('location')).toContain('done=passkey_added');

		const held = await getPasskeyStore().listOf(acme.bucketId, who.accountId);
		expect(held.length).toBe(1);
		expect(held[0]?.createdVia).toBe('federated_mail');
	});

	it('hides Two-step verification on /account/security for passwordless passkey-only accounts (FR-023)', async () => {
		const who = await person(acme.bucketId);
		await getUserStore(acme.bucketId).update(who.accountId, {
			passwordSet: false
		});
		await seedPasskey(acme.bucketId, who.accountId);
		const bucket = present(
			await getBucketStore().find(acme.bucketId),
			'acme bucket'
		);
		const sess = new Session({
			accountId: who.accountId,
			bucketId: acme.bucketId,
			loginTs: epochTime(),
			amr: ['hwk', 'user'],
			acr: configuration.acrMap.phishing_resistant
		});
		const cookieVal = await sess.save(3600);
		const browser = new Browser(acme.origin);

		const res = await browser.request(securityPage(acme), {
			headers: { cookie: `${sessionCookieName(bucket)}=${cookieVal}` }
		});
		const html = await res.text();
		expect(html).toContain('Passkeys');
		expect(html).not.toContain('Two-step verification');
	});

	it('closes S10 Attack C: refuses auto-linking an unlinked federated sign-in onto a passwordless account holding a passkey', async () => {
		await getBucketStore().update(acme.bucketId, {
			passwordLogin: false,
			passkeyLogin: true
		});
		const who = await person(acme.bucketId);
		await getUserStore(acme.bucketId).update(who.accountId, {
			passwordSet: false
		});
		await seedPasskey(acme.bucketId, who.accountId);

		const bucket = present(
			await getBucketStore().find(acme.bucketId),
			'acme bucket'
		);
		const provider = present(bucket.federation[0], 'corp-sso provider');
		const outcome = await decideFederatedAccount({
			bucket,
			provider,
			subject: 'new-unlinked-sub',
			claims: {
				email: who.email,
				email_verified: true
			}
		});
		expect(outcome.kind).toBe('password_required');
	});
});
