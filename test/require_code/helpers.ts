import { expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { encodeParams } from '../test_helper.js';
import { present, shaped } from '../shape.ts';
import {
	Browser,
	codeFor,
	linkIn,
	PASSWORD
} from '../two_step_page/helpers.ts';

export {
	Browser,
	codeFor,
	linkIn,
	mailOn,
	mailsTo,
	person,
	project,
	textOf
} from '../two_step_page/helpers.ts';

export const CODE_APP = 'billing';
export const PLAIN_APP = 'timesheets';

export interface Reached {
	auth: AuthorizationRequest;
	response: Response;
	url: string;
}

export function uidIn(url: string): string {
	return present(/\/ui\/([^/]+)\//.exec(url)?.[1], `a sign-in at ${url}`);
}

/* The props a sign-in page hydrates from: what the server rendered it with. */
export function propsOf(html: string): Record<string, unknown> {
	const props = /window\.PROPS=(\{.*?\})<\/script>/s.exec(html)?.[1];
	return shaped(
		Type.Record(Type.String(), Type.Unknown()),
		JSON.parse(present(props, 'a props script'))
	);
}

/* Opens the application's sign-in in this browser and follows it to the first page that stops it. */
export async function openApp(
	browser: Browser,
	clientId = CODE_APP,
	extra: Record<string, string> = {}
): Promise<Reached> {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid',
		...extra
	});
	const { response, url } = await browser.open(
		`/auth?${encodeParams(auth.params)}`
	);
	return { auth, response, url };
}

/* Types the password on the login page reached, as a person would, and follows where it leads. */
export async function typePassword(
	browser: Browser,
	loginUrl: string,
	email: string
): Promise<{ response: Response; url: string }> {
	expect(loginUrl).toMatch(/\/ui\/[^/]+\/login$/);
	const posted = await browser.request(loginUrl, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			username: email,
			password: PASSWORD
		}).toString()
	});
	const location = present(posted.headers.get('location'), 'a redirect');
	return browser.open(new URL(location, loginUrl).toString());
}

/* A password sign-in to the application: open it, type the password, land wherever that leads. */
export async function signInTo(
	browser: Browser,
	email: string,
	clientId = CODE_APP,
	extra: Record<string, string> = {}
): Promise<Reached> {
	const opened = await openApp(browser, clientId, extra);
	const landed = await typePassword(browser, opened.url, email);
	return { auth: opened.auth, ...landed };
}

/* The secret the enrolment page offers, as the person would copy it into an authenticator. */
export async function offeredSecret(
	browser: Browser,
	uid: string
): Promise<string> {
	const page = await browser.request(`/ui/${uid}/totp/enroll`);
	const { secretText } = propsOf(await page.text());
	expect(typeof secretText).toBe('string');
	return String(secretText).replace(/\s+/g, '');
}

/* From the refusal page: set up, open the mailed link here, type the code shown; answers where that led. */
export async function setUpAndContinue(
	browser: Browser,
	refusalUrl: string,
	email: string
): Promise<{ response: Response; url: string; secret: string }> {
	const uid = uidIn(refusalUrl);
	const mailed = await browser.open(`/ui/${uid}/totp/enroll`);
	expect(mailed.response.status).toBe(200);
	await browser.open(linkIn(email, `/ui/${uid}/totp/enroll/link`));
	const secret = await offeredSecret(browser, uid);
	const confirmed = await browser.post(`/ui/${uid}/totp/enroll`, {
		code: codeFor(secret)
	});
	const location = present(confirmed.headers.get('location'), 'a resume');
	const landed = await browser.open(
		new URL(location, browser.url(`/ui/${uid}/`)).toString()
	);
	return { ...landed, secret };
}

/* The `acr` the application receives in the ID token for the code it got. */
export async function acrOf(
	auth: AuthorizationRequest,
	url: string
): Promise<string | undefined> {
	const code = present(
		new URL(url).searchParams.get('code'),
		`a code at ${url}`
	);
	const { data } = await auth.getToken(code);
	const idToken = present(
		(data as { id_token?: string } | null)?.id_token,
		'an ID token'
	);
	const payload = present(idToken.split('.')[1], 'an ID token payload');
	return shaped(
		Type.Object({ acr: Type.Optional(Type.String()) }),
		JSON.parse(Buffer.from(payload, 'base64url').toString())
	).acr;
}
