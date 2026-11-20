import { beforeAll, beforeEach, describe, expect, it } from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { present, shaped } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	Browser,
	claimsOf,
	holdingPasskey,
	mailOn,
	person,
	project,
	redeem,
	signInWithPasskey,
	type Project
} from './helpers.ts';
import {
	atOffer,
	createAtOffer,
	holdsCode,
	leaveOffer,
	offerIn,
	passwordSignIn
} from './offer_helpers.ts';

const PASSWORD_CONTEXT = 'urn:example:acr:pwd';
const MULTI_FACTOR = 'urn:example:acr:mfa';
const PHISHING_RESISTANT = 'urn:example:acr:phr';

let acme: Project;

function essential(...values: string[]): Record<string, string> {
	return {
		claims: JSON.stringify({ id_token: { acr: { essential: true, values } } })
	};
}

/* The context an app is told after a full passkey sign-in to a request with these parameters. */
async function afterPasskey(
	parameters: Record<string, string> = {}
): Promise<Record<string, unknown>> {
	const { device } = await holdingPasskey(acme);
	const { auth, code } = await signInWithPasskey(
		new Browser(acme.origin),
		device,
		acme,
		parameters
	);
	return claimsOf((await redeem(acme, auth, code)).id_token);
}

/* Where a sign-in with a password, and a code when `code`, ends for a request with these parameters. */
async function afterPassword(
	parameters: Record<string, string>,
	{ code }: { code: boolean }
): Promise<{ url: URL; claims?: Record<string, unknown> }> {
	const { email, accountId } = await person(acme.bucketId);
	if (code) await holdsCode(acme, accountId);
	const landed = await passwordSignIn(acme, email, {
		device: false,
		parameters
	});
	const url = new URL(landed.url);
	const issued = url.searchParams.get('code');
	if (issued === null) return { url };
	return {
		url,
		claims: claimsOf((await redeem(acme, landed.auth, issued)).id_token)
	};
}

/* A person holding only a conditional passkey, made at the offer after a password alone (specs/141). */
async function conditionalHeld(): Promise<SoftAuthenticator> {
	const { email } = await person(acme.bucketId);
	const landed = await passwordSignIn(acme, email);
	expect(atOffer(landed)).toBe(true);
	const device = new SoftAuthenticator();
	const created = await createAtOffer(acme, landed, device);
	expect(offerIn(await created.text())).toMatchObject({ conditional: true });
	await leaveOffer(landed, 'continue');
	return device;
}

const Refreshed = Type.Object({ id_token: Type.String() });

/* The ID token a refresh of the sign-in's refresh token carries. */
async function refreshedContext(
	parameters: Record<string, string>
): Promise<unknown> {
	const { device } = await holdingPasskey(acme);
	const { auth, code } = await signInWithPasskey(
		new Browser(acme.origin),
		device,
		acme,
		{ scope: 'openid offline_access', prompt: 'consent', ...parameters }
	);
	const issued = await elysia.handle(
		new Request(`${acme.origin}${acme.prefix}/token`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				client_id: acme.clientId,
				code,
				code_verifier: auth.code_verifier,
				redirect_uri: present(auth.params.redirect_uri, 'a redirect URI')
			}).toString()
		})
	);
	const { refresh_token } = shaped(
		Type.Object({ refresh_token: Type.String() }),
		await issued.json()
	);
	const refreshed = await elysia.handle(
		new Request(`${acme.origin}${acme.prefix}/token`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'refresh_token',
				client_id: acme.clientId,
				refresh_token
			}).toString()
		})
	);
	expect(refreshed.status).toBe(200);
	return claimsOf(shaped(Refreshed, await refreshed.json()).id_token).acr;
}

beforeAll(async () => {
	await bootstrap(import.meta.url);
	acme = await project(ACME);
});

beforeEach(async () => {
	resetSentEmails();
	await mailOn();
});

/**
 * @proves An application that asks for a sign-in that cannot be phished is told so after a full passkey sign-in, is
 * told the multi-factor context after a password and a code, and is refused when it made the request essential.
 */
describe('an application asking for a phishing-resistant sign-in', () => {
	it('is told phr after a full passkey sign-in', async () => {
		const claims = await afterPasskey({ acr_values: PHISHING_RESISTANT });

		expect(claims.acr).toBe(PHISHING_RESISTANT);
		expect(claims.amr).toEqual(['pop', 'user', 'mfa']);
	});

	it('is told phr again when it refreshes that sign-in', async () => {
		expect(await refreshedContext({ acr_values: PHISHING_RESISTANT })).toBe(
			PHISHING_RESISTANT
		);
	});

	it('is told the multi-factor context after a password and a code', async () => {
		const { claims } = await afterPassword(
			{ acr_values: PHISHING_RESISTANT },
			{ code: true }
		);

		expect(claims?.acr).toBe(MULTI_FACTOR);
	});

	it('is refused a password and a code when phr is essential', async () => {
		const { url } = await afterPassword(essential(PHISHING_RESISTANT), {
			code: true
		});

		expect(url.searchParams.get('error')).toBe(
			'unmet_authentication_requirements'
		);
	});

	it('is told the multi-factor context when that is the other value it made essential', async () => {
		const { claims } = await afterPassword(
			essential(PHISHING_RESISTANT, MULTI_FACTOR),
			{ code: true }
		);

		expect(claims?.acr).toBe(MULTI_FACTOR);
	});
});

/**
 * @proves No sign-in but a full passkey reaches the phishing-resistant context: a password, or a conditional passkey,
 * asked for `phr`, is reported as the password it is.
 */
describe('reaching the phishing-resistant context', () => {
	it('is not reached by a password alone', async () => {
		const { claims } = await afterPassword(
			{ acr_values: PHISHING_RESISTANT },
			{ code: false }
		);

		expect(claims?.acr).toBe(PASSWORD_CONTEXT);
	});

	it('is not reached by a conditional passkey', async () => {
		const device = await conditionalHeld();

		const { auth, code } = await signInWithPasskey(
			new Browser(acme.origin),
			device,
			acme,
			{ acr_values: PHISHING_RESISTANT }
		);

		expect(claimsOf((await redeem(acme, auth, code)).id_token).acr).toBe(
			PASSWORD_CONTEXT
		);
	});
});

/**
 * @proves An application that never asked for `phr` sees after a passkey sign-in exactly what it saw before the
 * phishing-resistant context existed, and one that asked for a weaker context is told the context it asked for.
 */
describe('applications that did not ask for phr', () => {
	it('are told the multi-factor context and the passkey’s methods when they ask for nothing', async () => {
		const claims = await afterPasskey();

		expect(claims.acr).toBe(MULTI_FACTOR);
		expect(claims.amr).toEqual(['pop', 'user', 'mfa']);
	});

	it('are told the multi-factor context when they ask for it', async () => {
		expect((await afterPasskey({ acr_values: MULTI_FACTOR })).acr).toBe(
			MULTI_FACTOR
		);
	});

	it('are told the multi-factor context when they made it essential', async () => {
		expect((await afterPasskey(essential(MULTI_FACTOR))).acr).toBe(
			MULTI_FACTOR
		);
	});

	it('are told the stronger of the two contexts they ask for', async () => {
		expect(
			(
				await afterPasskey({
					acr_values: `${PASSWORD_CONTEXT} ${MULTI_FACTOR}`
				})
			).acr
		).toBe(MULTI_FACTOR);
	});

	it('are told the password context they asked for, with the methods actually used', async () => {
		const claims = await afterPasskey({ acr_values: PASSWORD_CONTEXT });

		expect(claims.acr).toBe(PASSWORD_CONTEXT);
		expect(claims.amr).toEqual(['pop', 'user', 'mfa']);
	});

	it('are let through when they made the password context essential', async () => {
		expect((await afterPasskey(essential(PASSWORD_CONTEXT))).acr).toBe(
			PASSWORD_CONTEXT
		);
	});

	it('are never told phr when they refresh a sign-in that did not ask for it', async () => {
		expect(await refreshedContext({})).toBe(MULTI_FACTOR);
	});
});
