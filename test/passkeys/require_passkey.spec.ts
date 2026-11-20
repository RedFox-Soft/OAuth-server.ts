import {
	afterAll,
	beforeAll,
	beforeEach,
	describe,
	expect,
	it
} from 'bun:test';
import { Type } from '@sinclair/typebox';

import bootstrap, { bindClientToBucket, changeClient } from '../test_helper.js';
import { elysia } from 'lib/index.ts';
import { resetSentEmails } from 'lib/mail/mailer.ts';
import { present, shaped } from '../shape.ts';
import { SoftAuthenticator } from './authenticator.ts';
import {
	ACME,
	Browser,
	codeAfter,
	holdingPasskey,
	latestMail,
	mailOn,
	person,
	postPasskey,
	project,
	propsIn,
	redeem,
	signInWithPasskey,
	type Project
} from './helpers.ts';
import { holdsCode, passwordSignIn, type Landed } from './offer_helpers.ts';

let acme: Project;
let lift: () => Promise<void>;

const PageProps = Type.Object({
	requirement: Type.Literal('passkey'),
	variant: Type.String(),
	created: Type.Optional(Type.String()),
	options: Type.Optional(Type.Unknown())
});

function pageOf(html: string) {
	return shaped(PageProps, propsIn(html));
}

async function requirePasskey(clientId: string, on: boolean) {
	await changeClient(clientId, { 'signIn.requirePasskey': on });
}

/* A sign-in with a password, and a code when the person holds one, that the requirement stops. */
async function stopped(
	email: string,
	parameters: Record<string, string> = {}
): Promise<Landed & { html: string }> {
	const landed = await passwordSignIn(acme, email, {
		device: false,
		parameters
	});
	expect(landed.url).toMatch(/\/ui\/[^/]+\/code-required$/);
	return { ...landed, html: await landed.response.clone().text() };
}

/* Creates a passkey on the page the browser stands at, as its script does. */
async function createOnPage(
	landed: Landed & { html: string },
	device: SoftAuthenticator
): Promise<string> {
	const { options } = pageOf(landed.html);
	const made = await device.create(
		options as Parameters<SoftAuthenticator['create']>[0],
		{ origin: acme.origin }
	);
	const answered = await landed.browser.post(landed.url, {
		action: 'create',
		credential: JSON.stringify(made)
	});
	expect(answered.status).toBe(200);
	return answered.text();
}

/* "Sign in with your passkey" from the page, through to the code the app receives. */
async function signInFromPage(
	landed: Landed,
	html: string,
	device: SoftAuthenticator
): Promise<string> {
	const link = present(
		/href="([^"]*\/login\?notice=passkey)"/.exec(html)?.[1],
		'the passkey link'
	);
	const login = await landed.browser.open(new URL(link, landed.url).toString());
	const page = { url: login.url, html: await login.response.text() };
	const posted = await postPasskey(landed.browser, device, acme, page);
	return codeAfter(landed.browser, posted, page.url);
}

async function tokenRequest(
	fields: Record<string, string>
): Promise<{ status: number; body: unknown }> {
	const response = await elysia.handle(
		new Request(`${acme.origin}${acme.prefix}/token`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams(fields).toString()
		})
	);
	return { status: response.status, body: await response.json() };
}

/* A device flow for `acme-tv`, confirmed in a browser by signing in with a passkey: the passkey door's answer. */
async function confirmedWithPasskey(
	device: SoftAuthenticator,
	extra: Record<string, string>
): Promise<{
	posted: Response;
	browser: Browser;
	from: string;
	device_code: string;
}> {
	const started = await elysia.handle(
		new Request(`${acme.origin}${acme.prefix}/device/auth`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				client_id: 'acme-tv',
				scope: 'openid',
				...extra
			}).toString()
		})
	);
	const { device_code, user_code } = shaped(
		Type.Object({ device_code: Type.String(), user_code: Type.String() }),
		await started.json()
	);
	const browser = new Browser(acme.origin);
	const entry = await browser.request(`${acme.prefix}/device`);
	const xsrf = present(
		/name="xsrf" value="([0-9a-f]+)"/.exec(await entry.text())?.[1],
		'the device page’s xsrf'
	);
	const login = await browser.open(`${acme.prefix}/device`, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ xsrf, user_code, confirm: 'yes' }).toString()
	});
	const posted = await postPasskey(browser, device, acme, {
		url: login.url,
		html: await login.response.text()
	});
	return { posted, browser, from: login.url, device_code };
}

beforeAll(async () => {
	await bootstrap(import.meta.url);
	acme = await project(ACME);
	await bindClientToBucket('acme-tv', acme.bucketId);
});

beforeEach(async () => {
	resetSentEmails();
	await mailOn();
	await requirePasskey(acme.clientId, true);
});

afterAll(async () => {
	await lift();
});

/**
 * @proves An application that requires a passkey lets in only a sign-in with a full passkey, and every grant for a
 * person — a code issued before it was required, a refresh of an earlier sign-in — is refused unless its sign-in
 * reached the phishing-resistant context.
 */
describe('an application that requires a passkey', () => {
	it('lets in a person who signs in with a passkey', async () => {
		const { device } = await holdingPasskey(acme);

		const { auth, code } = await signInWithPasskey(
			new Browser(acme.origin),
			device,
			acme
		);

		expect((await redeem(acme, auth, code)).id_token).toBeString();
	});

	it('stops a sign-in with a password and a code', async () => {
		const { email, accountId } = await person(acme.bucketId);
		await holdsCode(acme, accountId);

		const landed = await stopped(email);

		expect(pageOf(landed.html).variant).toBe('passkeyCreate');
	});

	it('refuses a code issued, before it was required, for a sign-in with a code', async () => {
		await requirePasskey(acme.clientId, false);
		const { email, accountId } = await person(acme.bucketId);
		await holdsCode(acme, accountId);
		const landed = await passwordSignIn(acme, email, { device: false });
		const code = present(
			new URL(landed.url).searchParams.get('code'),
			'a code'
		);
		await requirePasskey(acme.clientId, true);

		const answer = await tokenRequest({
			grant_type: 'authorization_code',
			client_id: acme.clientId,
			code,
			code_verifier: landed.auth.code_verifier,
			redirect_uri: present(landed.auth.params.redirect_uri, 'a redirect URI')
		});

		expect(answer.status).toBe(400);
		expect(answer.body).toMatchObject({ error: 'invalid_grant' });
	});

	it('refuses to refresh a sign-in that was not with a passkey', async () => {
		await requirePasskey(acme.clientId, false);
		const { email, accountId } = await person(acme.bucketId);
		await holdsCode(acme, accountId);
		const landed = await passwordSignIn(acme, email, {
			device: false,
			parameters: { scope: 'openid offline_access', prompt: 'consent' }
		});
		const issued = await tokenRequest({
			grant_type: 'authorization_code',
			client_id: acme.clientId,
			code: present(new URL(landed.url).searchParams.get('code'), 'a code'),
			code_verifier: landed.auth.code_verifier,
			redirect_uri: present(landed.auth.params.redirect_uri, 'a redirect URI')
		});
		const { refresh_token } = shaped(
			Type.Object({ refresh_token: Type.String() }),
			issued.body
		);
		await requirePasskey(acme.clientId, true);

		const answer = await tokenRequest({
			grant_type: 'refresh_token',
			client_id: acme.clientId,
			refresh_token
		});

		expect(answer.status).toBe(400);
		expect(answer.body).toMatchObject({ error: 'invalid_grant' });
	});
});

/**
 * @proves A person turned away by an application that requires a passkey is offered the step that gets them in from
 * where they stand — create one, confirm the one they made, or sign in with the one they hold — and creating one never
 * raises the sign-in in progress; returning hands the application `unmet_authentication_requirements`.
 */
describe('the page for an application that requires a passkey', () => {
	it('creates a full passkey after a password and a code, and lets the person in when they sign in with it', async () => {
		const { email, accountId } = await person(acme.bucketId);
		await holdsCode(acme, accountId);
		const landed = await stopped(email);
		const device = new SoftAuthenticator();

		const html = await createOnPage(landed, device);

		expect(pageOf(html)).toMatchObject({
			created: 'full',
			variant: 'passkeySignIn'
		});
		const code = await signInFromPage(landed, html, device);
		expect((await redeem(acme, landed.auth, code)).id_token).toBeString();
	});

	it('does not let the sign-in that created the passkey through without signing in with it', async () => {
		const { email, accountId } = await person(acme.bucketId);
		await holdsCode(acme, accountId);
		const landed = await stopped(email);
		await createOnPage(landed, new SoftAuthenticator());

		const asked = new URL(`${acme.origin}${acme.prefix}/auth`);
		for (const [name, value] of Object.entries(landed.auth.params)) {
			if (value !== undefined) asked.searchParams.set(name, String(value));
		}
		asked.searchParams.set('prompt', 'none');
		const again = await landed.browser.open(asked.toString());

		expect(new URL(again.url).searchParams.get('code')).toBeNull();
	});

	it('creates a conditional passkey after a password alone, mails about it, and asks to confirm it', async () => {
		const { email } = await person(acme.bucketId);
		const landed = await stopped(email);

		const html = await createOnPage(landed, new SoftAuthenticator());

		expect(pageOf(html)).toMatchObject({
			created: 'conditional',
			variant: 'passkeyConfirm'
		});
		expect(latestMail(email).text).toContain('passkey-confirm?token=');
	});

	it('offers the passkey a person already holds, and no new one', async () => {
		const { email } = await holdingPasskey(acme);

		const landed = await stopped(email);

		expect(pageOf(landed.html).variant).toBe('passkeySignIn');
		expect(pageOf(landed.html).options).toBeUndefined();
	});

	it('hands the application unmet_authentication_requirements when the person returns', async () => {
		const { email } = await person(acme.bucketId);
		const landed = await stopped(email);

		const posted = await landed.browser.post(landed.url, { action: 'return' });
		const ended = await landed.browser.open(
			new URL(
				present(posted.headers.get('location'), 'a redirect'),
				landed.url
			).toString()
		);

		expect(new URL(ended.url).searchParams.get('error')).toBe(
			'unmet_authentication_requirements'
		);
	});
});

/**
 * @proves A device confirmed with a passkey in a browser never meets a requirement of a passkey: the verification page
 * says why, and the device is given no token.
 */
describe('a device flow for an application that requires a passkey', () => {
	beforeAll(async () => {
		lift = async () => requirePasskey('acme-tv', false);
		await requirePasskey('acme-tv', true);
	});

	it('is refused, with the reason, even when confirmed with a passkey', async () => {
		const { device } = await holdingPasskey(acme);
		const { posted, browser, from, device_code } = await confirmedWithPasskey(
			device,
			{}
		);
		const refused = await browser.open(
			new URL(
				present(posted.headers.get('location'), 'a redirect'),
				from
			).toString()
		);
		expect(refused.url).toMatch(/\/ui\/[^/]+\/code-required$/);
		expect(pageOf(await refused.response.text()).variant).toBe('device');
		const polled = await tokenRequest({
			client_id: 'acme-tv',
			grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
			device_code
		});
		expect(polled.status).toBe(400);
		expect(polled.body).not.toHaveProperty('access_token');
	});

	it('never meets an essential request for phr, even when confirmed with a passkey', async () => {
		await requirePasskey('acme-tv', false);
		const { device } = await holdingPasskey(acme);

		const { device_code } = await confirmedWithPasskey(device, {
			claims: JSON.stringify({
				id_token: { acr: { essential: true, value: 'urn:example:acr:phr' } }
			})
		});

		const polled = await tokenRequest({
			client_id: 'acme-tv',
			grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
			device_code
		});
		expect(polled.status).toBe(400);
		expect(polled.body).not.toMatchObject({ error: 'authorization_pending' });
		await requirePasskey('acme-tv', true);
	});
});
