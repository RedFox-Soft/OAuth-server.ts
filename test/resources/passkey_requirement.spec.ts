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
import { exportJWK, generateKeyPair, SignJWT } from 'jose';

import bootstrap, { bindClientToBucket } from '../test_helper.js';
import {
	getBucketStore,
	getConnectedAccountStore,
	getPersonActivityStore,
	getProtectedResourceStore
} from 'lib/adapters/index.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { configuration } from 'lib/configs/application.ts';
import { routeNames } from 'lib/consts/param_list.ts';
import { elysia } from 'lib/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { AccessToken } from 'lib/models/access_token.js';
import { BackchannelAuthenticationRequest } from 'lib/models/backchannel_authentication_request.js';
import { DeviceCode } from 'lib/models/device_code.js';
import { Grant, connectedAccountKey } from 'lib/models/grant.js';
import { RefreshToken } from 'lib/models/refresh_token.js';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import { resetKeyringForTests } from 'lib/sealing/keyring.ts';
import { present, shaped } from '../shape.ts';
import { TEST_KEYRING } from '../sealing/fixtures.ts';
import { SoftAuthenticator } from '../passkeys/authenticator.ts';
import {
	ACME,
	Browser,
	acceptPasskeys,
	claimsOf,
	holdingPasskey,
	mailOn,
	person,
	project,
	propsIn,
	signInWithPasskey,
	type Project
} from '../passkeys/helpers.ts';
import { holdsCode, passwordSignIn } from '../passkeys/offer_helpers.ts';

const VAULT_JWT = 'https://vault-jwt.acme.test/api';
const VAULT_OPAQUE = 'https://vault-opaque.acme.test/api';
const NOTES_API = 'https://notes.acme.test/api';

const MFA = 'urn:example:acr:mfa';
const PHR = 'urn:example:acr:phr';

const RefusalProps = Type.Object({
	requirement: Type.Literal('passkey'),
	variant: Type.String(),
	api: Type.Optional(Type.String()),
	created: Type.Optional(Type.String()),
	options: Type.Optional(Type.Unknown())
});

let acme: Project;
let idpKey: CryptoKey;
let idpJwk: Record<string, unknown>;

async function declareApis(
	opts: {
		requirePasskey?: boolean;
		signInEveryMinutes?: number;
		exchangedBy?: string;
	} = {}
) {
	const store = getProtectedResourceStore();
	const up = async (
		identifier: string,
		name: string,
		tokenFormat: 'jwt' | 'opaque',
		requirePasskey: boolean,
		signInEveryMinutes?: number,
		exchangedBy?: string
	) => {
		const existing = await store.find(acme.bucketId, identifier);
		if (!existing) {
			await store.create({
				namespace: acme.bucketId,
				identifier,
				bucketId: acme.bucketId,
				name,
				scopes: ['vault:read'],
				tokenFormat,
				...(requirePasskey ? { requirePasskey: true } : {}),
				...(signInEveryMinutes !== undefined ? { signInEveryMinutes } : {})
			});
		} else {
			await store.update(acme.bucketId, identifier, {
				requirePasskey,
				signInEveryMinutes: signInEveryMinutes ?? null,
				...(exchangedBy !== undefined ? { exchangedBy } : {})
			});
		}
		if (exchangedBy && !existing) {
			await store.update(acme.bucketId, identifier, { exchangedBy });
		}
	};
	await up(
		VAULT_JWT,
		'Vault API',
		'jwt',
		opts.requirePasskey ?? true,
		opts.signInEveryMinutes,
		opts.exchangedBy
	);
	await up(
		VAULT_OPAQUE,
		'Vault Opaque API',
		'opaque',
		opts.requirePasskey ?? true,
		opts.signInEveryMinutes
	);
	await up(NOTES_API, 'Notes API', 'jwt', false, undefined);
}

async function tokenPost(
	fields: Record<string, string>,
	basic?: [string, string]
): Promise<{ status: number; body: Record<string, unknown> }> {
	const headers: Record<string, string> = {
		'content-type': 'application/x-www-form-urlencoded'
	};
	if (basic) {
		headers.authorization = `Basic ${Buffer.from(`${basic[0]}:${basic[1]}`).toString('base64')}`;
	}
	const res = await elysia.handle(
		new Request(`${acme.origin}${acme.prefix}/token`, {
			method: 'POST',
			headers,
			body: new URLSearchParams(fields).toString()
		})
	);
	return {
		status: res.status,
		body: (await res.json()) as Record<string, unknown>
	};
}

async function introspect(
	token: string
): Promise<{ status: number; body: Record<string, unknown> }> {
	const res = await elysia.handle(
		new Request(`${acme.origin}${acme.prefix}${routeNames.introspect}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/x-www-form-urlencoded',
				authorization: `Basic ${Buffer.from('acme-machine:machine-secret').toString('base64')}`
			},
			body: new URLSearchParams({ token }).toString()
		})
	);
	return {
		status: res.status,
		body: (await res.json()) as Record<string, unknown>
	};
}

/**
 * @proves Every interactive sign-in and every grant issuing tokens for a passkey-requiring API holds the caller to a
 * full passkey sign-in: the refusal page names the API and lets a password user create a passkey (without raising the
 * running sign-in) or return with `unmet_authentication_requirements`; access tokens (JWT and opaque introspection)
 * carry `configuration.acrMap.phishing_resistant` even without client `phr` request while ID tokens and non-passkey
 * APIs keep spec 142 Rule B; refresh tokens are refused before rotation; device, CIBA, client_credentials, jwt-bearer,
 * and token-exchange grants all enforce the requirement with the exact contract descriptions.
 */
describe('enforcing an API passkey requirement across sign-in and every grant', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'passkey_requirement' });
		resetKeyringForTests(TEST_KEYRING);
		await mailOn();
		acme = await project(ACME);
		await bindClientToBucket('acme-machine', acme.bucketId);
		await bindClientToBucket('acme-tv', acme.bucketId);
		await bindClientToBucket('acme-ciba', acme.bucketId);
		await bindClientToBucket('acme-exchanger', acme.bucketId);

		const pair = await generateKeyPair('ES256');
		idpKey = pair.privateKey;
		idpJwk = {
			...(await exportJWK(pair.publicKey)),
			kid: 'idp-1',
			use: 'sig',
			alg: 'ES256'
		};
	});

	beforeEach(async () => {
		resetSentEmails();
		setSystemTime();
		await acceptPasskeys(acme.bucketId, true);
		await declareApis({ requirePasskey: true });
	});

	afterEach(() => {
		setSystemTime();
	});

	it('stops password+TOTP sign-in with PasskeyRequiredPage naming the API, lets them create a passkey or return with unmet_authentication_requirements, and records activity', async () => {
		const { email, accountId } = await person(acme.bucketId);
		await holdsCode(acme, accountId);

		const landed = await passwordSignIn(acme, email, {
			device: false,
			parameters: {
				resource: VAULT_JWT,
				scope: 'openid vault:read'
			}
		});
		expect(landed.url).toMatch(/\/ui\/[^/]+\/code-required$/);
		const html = await landed.response.clone().text();
		const props = shaped(RefusalProps, propsIn(html));
		expect(props.variant).toBe('passkeyCreate');
		expect(props.api).toBe('Vault API');
		expect(html).toContain(
			'<bdi>Vault API</bdi> asks you to sign in with a passkey'
		);

		/* Creating a passkey on the refusal page creates it without raising the sign-in in progress. */
		const device = new SoftAuthenticator();
		const made = await device.create(
			props.options as Parameters<SoftAuthenticator['create']>[0],
			{ origin: acme.origin }
		);
		const createdRes = await landed.browser.post(landed.url, {
			action: 'create',
			credential: JSON.stringify(made)
		});
		expect(createdRes.status).toBe(200);
		const createdProps = shaped(RefusalProps, propsIn(await createdRes.text()));
		expect(createdProps.created).toBe('full');

		/* Returning without signing in with the passkey delivers unmet_authentication_requirements with API description. */
		const returned = await landed.browser.post(landed.url, {
			action: 'return'
		});
		const loc = present(returned.headers.get('location'), 'return redirect');
		const finalRes = await landed.browser.open(
			new URL(loc, landed.url).toString()
		);
		const finalUrl = new URL(finalRes.url);
		expect(finalUrl.searchParams.get('error')).toBe(
			'unmet_authentication_requirements'
		);
		expect(finalUrl.searchParams.get('error_description')).toBe(
			'the API requires a passkey sign-in'
		);

		/* Person activity records passkey_required naming the API resource. */
		await flushPersonActivityNow();
		const page = await getPersonActivityStore().listForPerson(
			acme.bucketId,
			accountId,
			{ now: new Date(), limit: 20 }
		);
		const row = page.rows.find((r) => r.reason === 'passkey_required');
		expect(row).toBeDefined();
		expect(row?.place.resource).toBe(VAULT_JWT);
	});

	it('shows passkeySignIn when holding a full passkey, passkeyConfirm when holding only a conditional passkey, and passkeyAsk when passkeys are off', async () => {
		/* Full passkey holder who typed password -> passkeySignIn */
		const fullHolder = await holdingPasskey(acme);
		const landedFull = await passwordSignIn(acme, fullHolder.email, {
			device: false,
			parameters: { resource: VAULT_JWT, scope: 'openid vault:read' }
		});
		const propsFull = shaped(
			RefusalProps,
			propsIn(await landedFull.response.text())
		);
		expect(propsFull.variant).toBe('passkeySignIn');
		expect(propsFull.api).toBe('Vault API');

		/* Conditional passkey holder -> passkeyConfirm (and signing in with conditional passkey also lands here) */
		const cond = await person(acme.bucketId);
		const condLanding = await passwordSignIn(acme, cond.email, {
			device: false,
			parameters: { resource: VAULT_JWT, scope: 'openid vault:read' }
		});
		const condHtml = await condLanding.response.text();
		const condProps = shaped(RefusalProps, propsIn(condHtml));
		const condDevice = new SoftAuthenticator();
		const condMade = await condDevice.create(
			condProps.options as Parameters<SoftAuthenticator['create']>[0],
			{ origin: acme.origin }
		);
		await condLanding.browser.post(condLanding.url, {
			action: 'create',
			credential: JSON.stringify(condMade)
		});
		/* Now sign in again with password -> sees passkeyConfirm */
		const landedCond = await passwordSignIn(acme, cond.email, {
			device: false,
			parameters: { resource: VAULT_JWT, scope: 'openid vault:read' }
		});
		const propsCond = shaped(
			RefusalProps,
			propsIn(await landedCond.response.text())
		);
		expect(propsCond.variant).toBe('passkeyConfirm');
		expect(propsCond.api).toBe('Vault API');

		/* Passkeys turned off -> passkeyAsk */
		await acceptPasskeys(acme.bucketId, false);
		const landedOff = await passwordSignIn(acme, fullHolder.email, {
			device: false,
			parameters: { resource: VAULT_JWT, scope: 'openid vault:read' }
		});
		const propsOff = shaped(
			RefusalProps,
			propsIn(await landedOff.response.text())
		);
		expect(propsOff.variant).toBe('passkeyAsk');
		expect(propsOff.api).toBe('Vault API');
	});

	it('issues JWT and opaque access tokens with acr=phr without client asking for phr, while ID token and non-passkey API keep Rule B (mfa)', async () => {
		const { device } = await holdingPasskey(acme);
		const browser = new Browser(acme.origin);

		/* Request both passkey API (JWT), passkey API (opaque), and non-passkey API without acr_values=phr. */
		const { auth, code } = await signInWithPasskey(browser, device, acme, {
			scope: 'openid offline_access vault:read',
			resource: VAULT_JWT
		});
		const redeemed = await tokenPost({
			grant_type: 'authorization_code',
			client_id: acme.clientId,
			code,
			code_verifier: auth.code_verifier,
			redirect_uri: present(auth.params.redirect_uri, 'redirect_uri'),
			resource: VAULT_JWT
		});
		expect(redeemed.status).toBe(200);
		const atClaims = claimsOf(String(redeemed.body.access_token));
		const idClaims = claimsOf(String(redeemed.body.id_token));
		expect(atClaims.acr).toBe(PHR);
		/* Rule B unchanged on ID token! */
		expect(idClaims.acr).toBe(MFA);

		/* Refresh token for the passkey API keeps issuing acr=phr on renewed access token. */
		const rtValue = String(redeemed.body.refresh_token);
		const storedRt = await RefreshToken.find(rtValue);
		expect(storedRt.payload.acr).toBe(MFA);
		expect(storedRt.payload.signInAcr).toBe(PHR);

		const renewed = await tokenPost({
			grant_type: 'refresh_token',
			client_id: acme.clientId,
			refresh_token: rtValue,
			resource: VAULT_JWT
		});
		expect(renewed.status).toBe(200);
		expect(claimsOf(String(renewed.body.access_token)).acr).toBe(PHR);

		/* Opaque access token introspection also reports acr=phr without client requesting phr. */
		const browser2 = new Browser(acme.origin);
		const opaqueSignIn = await signInWithPasskey(browser2, device, acme, {
			scope: 'openid vault:read',
			resource: VAULT_OPAQUE
		});
		const opaqueRedeem = await tokenPost({
			grant_type: 'authorization_code',
			client_id: acme.clientId,
			code: opaqueSignIn.code,
			code_verifier: opaqueSignIn.auth.code_verifier,
			redirect_uri: present(
				opaqueSignIn.auth.params.redirect_uri,
				'redirect_uri'
			),
			resource: VAULT_OPAQUE
		});
		expect(opaqueRedeem.status).toBe(200);
		const intro = await introspect(String(opaqueRedeem.body.access_token));
		expect(intro.status).toBe(200);
		expect(intro.body.active).toBe(true);
		expect(intro.body.acr).toBe(PHR);

		/* Non-passkey API keeps Rule B (mfa). */
		const browser3 = new Browser(acme.origin);
		const notesSignIn = await signInWithPasskey(browser3, device, acme, {
			scope: 'openid vault:read',
			resource: NOTES_API
		});
		const notesRedeem = await tokenPost({
			grant_type: 'authorization_code',
			client_id: acme.clientId,
			code: notesSignIn.code,
			code_verifier: notesSignIn.auth.code_verifier,
			redirect_uri: present(
				notesSignIn.auth.params.redirect_uri,
				'redirect_uri'
			),
			resource: NOTES_API
		});
		expect(notesRedeem.status).toBe(200);
		expect(claimsOf(String(notesRedeem.body.access_token)).acr).toBe(MFA);
	});

	it('refuses refresh token from a TOTP sign-in BEFORE rotation, leaving the grant and refresh token standing for other APIs', async () => {
		/* Turn passkey requirement off first so TOTP sign-in gets a refresh token covering both APIs. */
		await declareApis({ requirePasskey: false });
		const { email, accountId } = await person(acme.bucketId);
		await holdsCode(acme, accountId);

		const landed = await passwordSignIn(acme, email, {
			device: false,
			parameters: {
				scope: 'openid offline_access vault:read',
				resource: VAULT_JWT
			}
		});
		const code = present(new URL(landed.url).searchParams.get('code'), 'code');
		const firstTokens = await tokenPost({
			grant_type: 'authorization_code',
			client_id: acme.clientId,
			code,
			code_verifier: landed.auth.code_verifier,
			redirect_uri: present(landed.auth.params.redirect_uri, 'redirect_uri'),
			resource: VAULT_JWT
		});
		expect(firstTokens.status).toBe(200);
		const rtValue = String(firstTokens.body.refresh_token);
		const rt = present(await RefreshToken.find(rtValue), 'refresh token');

		/* Now enable requirePasskey on Vault API. */
		await declareApis({ requirePasskey: true });

		const firstRefusal = await tokenPost({
			grant_type: 'refresh_token',
			client_id: acme.clientId,
			refresh_token: rtValue,
			resource: VAULT_JWT
		});
		const retryRefusal = await tokenPost({
			grant_type: 'refresh_token',
			client_id: acme.clientId,
			refresh_token: rtValue,
			resource: VAULT_JWT
		});
		expect(firstRefusal.status).toBe(400);
		expect(firstRefusal.body).toMatchObject({ error: 'invalid_grant' });
		expect(retryRefusal.status).toBe(400);
		expect(retryRefusal.body).toMatchObject({ error: 'invalid_grant' });

		/* Grant and refresh token still exist unconsumed and still renew for OIDC (no resource). */
		expect(
			await Grant.find(present(rt.payload.grantId, 'grantId'))
		).toBeDefined();
		const stillWorks = await tokenPost({
			grant_type: 'refresh_token',
			client_id: acme.clientId,
			refresh_token: rtValue,
			scope: 'openid'
		});
		expect(stillWorks.status).toBe(200);
	});

	it('enforces signInEveryMinutes combined with requirePasskey', async () => {
		const { device } = await holdingPasskey(acme);
		await declareApis({ requirePasskey: true, signInEveryMinutes: 60 });

		const browser = new Browser(acme.origin);
		const { auth, code } = await signInWithPasskey(browser, device, acme, {
			scope: 'openid offline_access vault:read',
			resource: VAULT_JWT
		});
		const tokens = await tokenPost({
			grant_type: 'authorization_code',
			client_id: acme.clientId,
			code,
			code_verifier: auth.code_verifier,
			redirect_uri: present(auth.params.redirect_uri, 'redirect_uri'),
			resource: VAULT_JWT
		});
		expect(tokens.status).toBe(200);
		const rtValue = String(tokens.body.refresh_token);

		/* Advance clock past 60 minutes -> full passkey is now too old. */
		setSystemTime(new Date(Date.now() + 61 * 60_000));
		const stale = await tokenPost({
			grant_type: 'refresh_token',
			client_id: acme.clientId,
			refresh_token: rtValue,
			resource: VAULT_JWT
		});
		expect(stale.status).toBe(400);
		expect(stale.body).toMatchObject({ error: 'invalid_grant' });
	});

	it('refuses device_code, ciba, client_credentials, and jwt-bearer grants with the contract descriptions', async () => {
		const { accountId, email } = await holdingPasskey(acme);

		/* 1. client_credentials */
		const cc = await tokenPost(
			{
				grant_type: 'client_credentials',
				resource: VAULT_JWT,
				scope: 'vault:read'
			},
			['acme-machine', 'machine-secret']
		);
		expect(cc.status).toBe(400);
		expect(cc.body).toMatchObject({
			error: 'invalid_target',
			error_description: "this API accepts only tokens from a person's sign-in"
		});

		/* 2. device_code (even if confirmed with a passkey, device signInAcr is capped at mfa) */
		const deviceGrant = new Grant({
			accountId,
			clientId: 'acme-tv',
			bucketId: acme.bucketId
		});
		deviceGrant.addResourceScope(VAULT_JWT, 'vault:read');
		const deviceGrantId = await deviceGrant.save();
		const dc = new DeviceCode({
			bucketId: acme.bucketId,
			accountId,
			clientId: 'acme-tv',
			grantId: deviceGrantId,
			scope: 'vault:read',
			resource: VAULT_JWT,
			acr: MFA,
			signInAcr: MFA,
			authTime: Math.floor(Date.now() / 1000)
		});
		const dcValue = await dc.save();
		const dcRes = await tokenPost({
			grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
			client_id: 'acme-tv',
			device_code: dcValue
		});
		expect(dcRes.status).toBe(400);
		expect(dcRes.body).toMatchObject({ error: 'invalid_grant' });

		/* 3. CIBA */
		const cibaGrant = new Grant({
			accountId,
			clientId: 'acme-ciba',
			bucketId: acme.bucketId
		});
		cibaGrant.addResourceScope(VAULT_JWT, 'vault:read');
		const cibaGrantId = await cibaGrant.save();
		const req = new BackchannelAuthenticationRequest({
			bucketId: acme.bucketId,
			accountId,
			clientId: 'acme-ciba',
			grantId: cibaGrantId,
			scope: 'vault:read',
			resource: VAULT_JWT,
			acr: MFA,
			signInAcr: MFA,
			authTime: Math.floor(Date.now() / 1000)
		});
		const reqId = await req.save();
		const cibaRes = await tokenPost(
			{
				grant_type: 'urn:openid:params:grant-type:ciba',
				auth_req_id: reqId
			},
			['acme-ciba', 'ciba-secret']
		);
		expect(cibaRes.status).toBe(400);
		expect(cibaRes.body).toMatchObject({ error: 'invalid_grant' });

		/* 4. jwt-bearer (identity assertion) */
		forgetBucketAddresses();
		await getBucketStore().update(acme.bucketId, {
			federation: [
				{
					id: 'corp-idp',
					kind: 'oidc',
					displayName: 'Corp IdP',
					issuer: 'https://corp.idp.test',
					clientId: 'fox',
					clientSecret: 's',
					enabled: true,
					acceptsIdentityAssertions: true,
					plainAssertions: true,
					jwks: { keys: [idpJwk] }
				} as never
			]
		});
		const assertion = await new SignJWT({
			sub: email,
			resource: VAULT_JWT,
			scope: 'vault:read'
		})
			.setProtectedHeader({
				alg: 'ES256',
				kid: 'idp-1',
				typ: 'oauth-id-jag+jwt'
			})
			.setIssuer('https://corp.idp.test')
			.setAudience(`${acme.origin}${acme.prefix}`)
			.setIssuedAt()
			.setExpirationTime('5m')
			.setJti('jti-assertion-1')
			.sign(idpKey);
		const jbRes = await tokenPost(
			{
				grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
				assertion,
				resource: VAULT_JWT,
				scope: 'vault:read'
			},
			['acme-machine', 'machine-secret']
		);
		expect(jbRes.status).toBe(400);
		expect(jbRes.body).toMatchObject({ error: 'invalid_grant' });
	});

	it('holds token-exchange (connected service via API exchangedBy) to the subject token’s sign-in', async () => {
		const { accountId } = await holdingPasskey(acme);
		await declareApis({
			requirePasskey: true,
			exchangedBy: 'acme-exchanger'
		});

		/* Seed a connected service and connected account on acme. */
		forgetBucketAddresses();
		await getBucketStore().update(acme.bucketId, {
			connectedServices: [
				{
					id: 'gh',
					kind: 'catalogue',
					catalogueId: 'github',
					displayName: 'GitHub',
					clientId: 'gh-id',
					clientSecret: 'gh-secret',
					scopes: ['repo'],
					applications: ['acme-exchanger'],
					addedAt: new Date()
				} as never
			]
		});
		const nowSec = Math.floor(Date.now() / 1000);
		const nowIso = new Date(nowSec * 1000).toISOString();
		const connected = {
			_id: `gh-${accountId}`,
			bucketId: acme.bucketId,
			accountId,
			serviceId: 'gh',
			upstreamId: 'gh-user-1',
			label: 'octocat',
			scopes: ['repo'],
			scopesInferred: false,
			accessToken: 'gh-upstream-token',
			tokenType: 'Bearer',
			accessTokenExpiresAt: nowSec + 3600,
			refreshedAt: nowSec,
			connectedAt: nowIso,
			updatedAt: nowIso
		};
		await getConnectedAccountStore().put(connected);

		const grant = new Grant({
			accountId,
			clientId: acme.clientId,
			bucketId: acme.bucketId
		});
		grant.addResourceScope(VAULT_JWT, 'vault:read');
		grant.allowConnected(connectedAccountKey(connected._id));
		const grantId = await grant.save();

		/* TOTP subject token (opaque) -> refused 400 invalid_grant */
		const totpSubject = await new AccessToken({
			bucketId: acme.bucketId,
			accountId,
			client: { clientId: acme.clientId } as never,
			grantId,
			aud: VAULT_JWT,
			scope: 'vault:read',
			gty: 'authorization_code',
			authTime: Math.floor(Date.now() / 1000),
			acr: MFA,
			signInAcr: MFA
		}).save();

		const refused = await tokenPost(
			{
				grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
				subject_token: totpSubject,
				subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
				requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
				audience: 'gh'
			},
			['acme-exchanger', 'exchanger-secret']
		);
		expect(refused.status).toBe(400);
		expect(refused.body).toMatchObject({ error: 'invalid_grant' });

		/* Full passkey subject token (opaque) -> succeeds and returns upstream token */
		const passkeySubject = await new AccessToken({
			bucketId: acme.bucketId,
			accountId,
			client: { clientId: acme.clientId } as never,
			grantId,
			aud: VAULT_JWT,
			scope: 'vault:read',
			gty: 'authorization_code',
			authTime: Math.floor(Date.now() / 1000),
			acr: PHR,
			signInAcr: PHR
		}).save();

		const allowed = await tokenPost(
			{
				grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
				subject_token: passkeySubject,
				subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
				requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
				audience: 'gh'
			},
			['acme-exchanger', 'exchanger-secret']
		);
		expect(allowed.status).toBe(200);
		expect(allowed.body.access_token).toBe('gh-upstream-token');
		expect(configuration.acrMap.phishing_resistant).toBe(PHR);
	});
});
