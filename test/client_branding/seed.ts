import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import { encodeBase32 } from 'lib/totp/base32.ts';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import {
	bindClientToBucket,
	changeClient,
	seedBucket
} from '../test_helper.js';

export const PASSWORD = 'correct horse battery';
export const ACME = 'acme';
export const ACME_TWO_STEP = 'acme-two-step';
export const MEMBER = 'member@acme.test';
export const ENROLLED = 'enrolled@acme.test';
export const UNENROLLED = 'unenrolled@acme.test';

/* A colour as an administrator would have stored it — the stored record, never the client object. */
export async function giveColour(clientId: string, colour: string) {
	return changeClient(clientId, { primaryColor: colour });
}

async function account(bucketId: string, email: string, totp = false) {
	const user = await getUserStore(bucketId).create(
		email,
		await Bun.password.hash(PASSWORD),
		true
	);
	if (totp) {
		await getUserStore(bucketId).update(user._id, {
			totp: {
				secret: encodeBase32(Buffer.from('12345678901234567890', 'ascii')),
				enrolledAt: new Date(),
				lastStep: 0
			}
		});
	}
}

/*
 * The organization's own projects: `acme`, open for sign-up, holding the own apps; `acme-two-step`, which
 * asks every sign-in for a second step. Each app belongs to its project as one an administrator created
 * there does (specs/099), which is what makes it the organization's own for a person of that project.
 */
export async function ownProjects(): Promise<void> {
	await seedBucket({
		bucketId: ACME,
		clientId: 'own-app',
		accountId: 'acme-member'
	});
	await getBucketStore().update(ACME, { registrationOpen: true });
	for (const clientId of [
		'own-plain',
		'own-second',
		'own-loopback',
		'own-device'
	])
		await bindClientToBucket(clientId, ACME);
	await account(ACME, MEMBER);

	await seedBucket({
		bucketId: ACME_TWO_STEP,
		clientId: 'own-two-step',
		accountId: 'two-step-member'
	});
	await getBucketStore().update(ACME_TWO_STEP, { totpRequired: true });
	await account(ACME_TWO_STEP, ENROLLED, true);
	await account(ACME_TWO_STEP, UNENROLLED);
}

/* A browser: it keeps the cookies it is given and sends them all back. */
export class Browser {
	#jar = new Map<string, string>();

	constructor(cookie = '') {
		for (const pair of cookie.split('; ').filter(Boolean)) {
			const eq = pair.indexOf('=');
			if (eq > 0) this.#jar.set(pair.slice(0, eq), pair.slice(eq + 1));
		}
	}

	async request(path: string, init: RequestInit = {}): Promise<Response> {
		const response = await elysia.handle(
			new Request(path.startsWith('http') ? path : `${ISSUER}${path}`, {
				redirect: 'manual',
				...init,
				headers: {
					...(init.headers as Record<string, string>),
					cookie: this.cookie
				}
			})
		);
		for (const set of response.headers.getSetCookie()) {
			const [pair] = set.split(';');
			const at = pair.indexOf('=');
			const value = pair.slice(at + 1);
			if (set.includes('Thu, 01 Jan 1970') || !value)
				this.#jar.delete(pair.slice(0, at));
			else this.#jar.set(pair.slice(0, at), value);
		}
		return response;
	}

	post(path: string, fields: Record<string, string>): Promise<Response> {
		return this.request(path, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams(fields).toString()
		});
	}

	get cookie(): string {
		return [...this.#jar].map(([k, v]) => `${k}=${v}`).join('; ');
	}
}

export interface Page {
	path: string;
	html: string;
}

function relative(location: string | null): string {
	if (!location) throw new Error('expected a redirect');
	return location.startsWith(ISSUER) ? location.slice(ISSUER.length) : location;
}

/* Starts an authorization request for `clientId` and answers the interaction page it leads to. */
export async function start(
	clientId: string,
	browser = new Browser(),
	params: Record<string, unknown> = {}
): Promise<{ browser: Browser; uid: string; at: string }> {
	// `prompt=consent`: a seeded session already allowed `openid`, and the consent page is one of the pages.
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid',
		prompt: 'consent',
		...params
	});
	const response = await auth.authorize({
		headers: { cookie: browser.cookie }
	});
	const at = relative(response.headers.get('location'));
	return {
		browser: new Browser(joinCookies(browser.cookie, response)),
		uid: at.split('/')[2],
		at
	};
}

function joinCookies(cookie: string, response: Response): string {
	const jar = new Map<string, string>();
	for (const pair of cookie.split('; ').filter(Boolean)) {
		const eq = pair.indexOf('=');
		if (eq > 0) jar.set(pair.slice(0, eq), pair.slice(eq + 1));
	}
	for (const raw of response.headers.getSetCookie()) {
		const [pair] = raw.split(';');
		const eq = pair.indexOf('=');
		if (eq > 0) jar.set(pair.slice(0, eq), pair.slice(eq + 1));
	}
	return [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
}

export async function open(browser: Browser, path: string): Promise<Page> {
	const response = await browser.request(path);
	if (response.status !== 200 && response.status !== 400)
		throw new Error(`${path} answered ${response.status}`);
	return { path, html: await response.text() };
}

/* The sign-in page an app's authorization request opens on, for someone not yet signed in. */
export async function signInPage(
	clientId: string,
	params: Record<string, unknown> = {}
): Promise<Page> {
	const { browser, at } = await start(clientId, new Browser(), params);
	return open(browser, at);
}

export async function registrationPage(clientId: string): Promise<Page> {
	const { browser, uid } = await start(clientId);
	return open(browser, `/ui/${uid}/registration`);
}

/* The two-step page after a correct password — the code page, or enrolment for an account without one. */
export async function twoStepPage(email: string): Promise<Page> {
	const { browser, uid } = await start('own-two-step');
	const signedIn = await browser.post(`/ui/${uid}/login`, {
		username: email,
		password: PASSWORD
	});
	return open(browser, relative(signedIn.headers.get('location')));
}

/* The consent page, for a person already signed in to the project the app signs them in to. */
export async function consentPage(
	clientId: string,
	cookie: string,
	params: Record<string, unknown> = {}
): Promise<Page> {
	const { browser, at } = await start(clientId, new Browser(cookie), params);
	if (!at.endsWith('/consent')) throw new Error(`expected consent, got ${at}`);
	return open(browser, at);
}

/*
 * The sign-in and consent pages of a device's sign-in: a device asks for a code, the person enters it in a
 * fresh browser, signs in, and lands on consent.
 */
export async function devicePages(
	clientId: string,
	email: string,
	fields: Record<string, string> = {}
): Promise<{ signIn: Page; consent: Page }> {
	const authorized = await elysia.handle(
		new Request(`${ISSUER}/device/auth`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				client_id: clientId,
				scope: 'openid',
				...fields
			})
		})
	);
	const { user_code } = (await authorized.json()) as { user_code: string };
	const browser = new Browser();
	const entry = await (await browser.request('/device')).text();
	const xsrf = /name="xsrf" value="([0-9a-f]+)"/.exec(entry)?.[1] ?? '';
	const confirmed = await browser.post('/device', {
		xsrf,
		user_code,
		confirm: 'yes'
	});
	const loginAt = relative(confirmed.headers.get('location'));
	const signIn = await open(browser, loginAt);
	const signedIn = await browser.post(loginAt, {
		username: email,
		password: PASSWORD
	});
	const consent = await open(
		browser,
		relative(signedIn.headers.get('location'))
	);
	return { signIn, consent };
}

/* What a branded page carries, as the browser would read it. */
export function painted(html: string) {
	const props = JSON.parse(
		/window\.PROPS=(.*?)<\/script>/s.exec(html)?.[1] ?? '{}'
	) as { accent?: unknown };
	const darkAt = html.indexOf(
		'<style>@media (prefers-color-scheme: dark){:root '
	);
	const light = darkAt === -1 ? html : html.slice(0, darkAt);
	const dark = darkAt === -1 ? '' : html.slice(darkAt);
	const value = (css: string, name: string) =>
		new RegExp(`--ant-${name}:([^;}]+)`).exec(css)?.[1];
	const link =
		/<style>:root\{--fox-link:(#[0-9a-f]{6})\}@media \(prefers-color-scheme: dark\)\{:root\{--fox-link:(#[0-9a-f]{6})\}\}<\/style>/.exec(
			html
		);
	return {
		props,
		light,
		dark,
		lightPrimary: value(light, 'color-primary'),
		darkPrimary: value(dark, 'color-primary'),
		foxLink: link ? { light: link[1], dark: link[2] } : undefined
	};
}
