import { expect } from 'bun:test';
import { Type } from '@sinclair/typebox';
import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/server';

import {
	getBucketStore,
	getPasskeyStore,
	getUserStore
} from 'lib/adapters/index.ts';
import type { Passkey, UserBucket } from 'lib/adapters/types.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { forgetBucketAddresses } from 'lib/admin/auth/bucketAddress.ts';
import { sessionCookieName } from 'lib/consts/param_list.ts';
import { decode as decodeJWT } from 'lib/helpers/jwt.ts';
import { elysia } from 'lib/index.ts';
import { Session } from 'lib/models/session.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { bindClientToBucket, encodeParams } from '../test_helper.ts';
import { present, shaped } from '../shape.ts';
import {
	Browser,
	PASSWORD,
	pageOf,
	person,
	signInThroughPage,
	textOf,
	xsrfFrom
} from '../connected_apps/helpers.ts';
import { codeFor, linkIn, mailOn, mailsTo } from '../two_step_page/helpers.ts';
import {
	SoftAuthenticator,
	type BrowserContext,
	type CreateChoices,
	type GetChoices
} from './authenticator.ts';

export { Browser, PASSWORD, linkIn, mailOn, mailsTo, person, textOf, xsrfFrom };

/*
 * The three projects of test/passkeys/passkeys.config.ts. `prefix` is what a path project's addresses start with;
 * `origin` is the origin a browser shows for its pages, which is also the origin a passkey made there is bound to.
 */
export interface Project {
	bucketId: string;
	clientId: string;
	prefix: string;
	origin: string;
}

export const ACME = { slug: 'acme', clientId: 'acme-app' } as const;
export const BETA = { slug: 'beta', clientId: 'beta-app' } as const;
export const SUB = { slug: 'sub', clientId: 'sub-app' } as const;

/* A project at a path of the instance (`http://e.ly/<slug>`), or at a subdomain of it (`http://<slug>.e.ly`). */
export async function project(
	{ slug, clientId }: { slug: string; clientId: string },
	{
		subdomain = false,
		passkeys = true,
		settings = {}
	}: {
		subdomain?: boolean;
		passkeys?: boolean;
		settings?: Partial<
			Pick<UserBucket, 'totpRequired' | 'totpSelfService' | 'passwordLogin'>
		>;
	} = {}
): Promise<Project> {
	forgetBucketAddresses();
	const bucket = await getBucketStore().create({
		ownerGroupId: UNASSIGNED_GROUP_ID,
		name: `${slug} people`,
		slug,
		...(subdomain ? { subdomain: true as const } : {})
	});
	await bindClientToBucket(clientId, bucket._id);
	await acceptPasskeys(bucket._id, passkeys, settings);
	return {
		bucketId: bucket._id,
		clientId,
		prefix: subdomain ? '' : `/${slug}`,
		origin: subdomain ? `http://${slug}.e.ly` : 'http://e.ly'
	};
}

/*
 * The project's "Passkeys" setting written to its record. The admin route that turns it on is proved in
 * project_setting.spec.ts; the other specs only need the setting to be in place.
 */
export async function acceptPasskeys(
	bucketId: string,
	on = true,
	settings: Partial<
		Pick<UserBucket, 'totpRequired' | 'totpSelfService' | 'passwordLogin'>
	> = {}
): Promise<void> {
	forgetBucketAddresses();
	await getBucketStore().update(bucketId, { passkeyLogin: on, ...settings });
}

/* The account page's address in a project. */
export function securityPage(at: Project): string {
	return `${at.prefix}/account/security`;
}

function unescapeAttribute(value: string): string {
	return value
		.replace(/&quot;/g, '"')
		.replace(/&#39;|&#x27;/g, "'")
		.replace(/&lt;/g, '<')
		.replace(/&gt;/g, '>')
		.replace(/&amp;/g, '&');
}

const CreationOptions = Type.Object({
	challenge: Type.String(),
	rp: Type.Object({ id: Type.Optional(Type.String()), name: Type.String() }),
	user: Type.Object({
		id: Type.String(),
		name: Type.String(),
		displayName: Type.String()
	})
});

/* The creation options the page's add form hands its script, as the script reads them. */
export function creationOptionsIn(
	html: string
): PublicKeyCredentialCreationOptionsJSON {
	const raw = present(
		/data-options="([^"]*)"/.exec(html)?.[1],
		'the add form’s creation options'
	);
	const parsed: unknown = JSON.parse(unescapeAttribute(raw));
	shaped(CreationOptions, parsed);
	return parsed as PublicKeyCredentialCreationOptionsJSON;
}

/*
 * Adds a passkey on the account page of a browser whose session may add one now (a strong recent sign-in, or a
 * followed mailed link): reads the creation options off the page, lets the device make the passkey, and posts it the
 * way the page's script does. Answers the page's answer.
 */
export async function addOnPage(
	browser: Browser,
	device: SoftAuthenticator,
	at: Project,
	choices: CreateChoices = {}
): Promise<Response> {
	const page = await browser.request(securityPage(at));
	return postAdd(browser, device, at, await page.text(), choices);
}

/* A browser that says it is Chrome on Windows, as the one adding a passkey does in these cases. */
export const CHROME_ON_WINDOWS =
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

/* Posts the device's answer to the add form of a page already read, as the page's script does. */
export async function postAdd(
	browser: Browser,
	device: SoftAuthenticator,
	at: Project,
	html: string,
	choices: CreateChoices = {},
	origin = at.origin
): Promise<Response> {
	const options = creationOptionsIn(html);
	const credential = await device.create(options, { origin }, choices);
	return browser.post(
		securityPage(at),
		{
			action: 'passkey_add',
			xsrf: xsrfFrom(html),
			credential: JSON.stringify(credential)
		},
		{ 'user-agent': CHROME_ON_WINDOWS }
	);
}

/* The sign-in session this browser holds in the project. */
export async function sessionOf(
	browser: Browser,
	at: Project
): Promise<Session> {
	const bucket = present(
		await getBucketStore().find(at.bucketId),
		'the project'
	);
	const name = sessionCookieName(bucket);
	const id = present(
		browser.cookie
			.split('; ')
			.find((pair) => pair.startsWith(`${name}=`))
			?.slice(name.length + 1),
		'a session cookie'
	);
	return present(await Session.tryFind(id), 'the session');
}

/*
 * The proof a person's sign-in in this browser gave: a password alone, a password and a code from an authenticator
 * app (signed in through the real code step), or a passkey (added on their page after a code, then signed in with
 * through the passkey door in this browser).
 */
export type Proof = 'password' | 'code' | 'passkey';

const SECRET = 'JBSWY3DPEHPK3PXP';

export async function signedIn(
	at: Project,
	proof: Proof,
	/* An account already in the project, signed in to instead of a new person's (password and code only). */
	who?: { email: string; accountId: string }
): Promise<{ browser: Browser; email: string; accountId: string }> {
	if (proof === 'passkey') {
		const held = await holdingPasskey(at, { keepCode: true });
		const browser = await signedInWithPasskey(at, held.device);
		return { browser, email: held.email, accountId: held.accountId };
	}
	const { email, accountId } = who ?? (await person(at.bucketId));
	const browser = new Browser(at.origin);
	if (proof === 'code') {
		await getUserStore(at.bucketId).update(accountId, {
			totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0, via: 'self' }
		});
		const login = await browser.open(pageOf(at.prefix));
		const posted = await browser.request(login.url, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ username: email, password: PASSWORD })
		});
		const asked = new URL(
			present(posted.headers.get('location'), 'the code step'),
			login.url
		).toString();
		expect(asked).toMatch(/\/totp$/);
		const answered = await browser.request(asked, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ code: codeFor(SECRET) })
		});
		await browser.open(
			new URL(
				present(answered.headers.get('location'), 'a resume'),
				asked
			).toString()
		);
	} else {
		const landed = await signInThroughPage(browser, email, at.prefix);
		expect(landed.status).toBe(200);
	}
	return { browser, email, accountId };
}

/*
 * A person of the project holding one passkey on `device`, added on their own page after a password and a code, as
 * anyone would. Without `keepCode` their authenticator app is then removed, for a case about someone who holds none.
 * Needs mail on (`mailOn()`): every add is mailed about.
 */
export async function holdingPasskey(
	at: Project,
	{ keepCode = false }: { keepCode?: boolean } = {}
): Promise<{
	email: string;
	accountId: string;
	device: SoftAuthenticator;
}> {
	const { browser, email, accountId } = await signedIn(at, 'code');
	const device = new SoftAuthenticator();
	const added = await addOnPage(browser, device, at);
	expect(added.headers.get('location')).toContain('done=passkey_added');
	if (!keepCode) {
		await getUserStore(at.bucketId).update(accountId, { totp: undefined });
	}
	return { email, accountId, device };
}

/* A fresh browser signed in to the person's own page with the passkey on `device`, through the passkey door. */
export async function signedInWithPasskey(
	at: Project,
	device: SoftAuthenticator
): Promise<Browser> {
	const browser = new Browser(at.origin);
	const login = await browser.open(securityPage(at));
	expect(login.url).toMatch(/\/ui\/[^/]+\/login$/);
	const posted = await postPasskey(browser, device, at, {
		url: login.url,
		html: await login.response.text()
	});
	const landed = await browser.open(
		new URL(
			present(posted.headers.get('location'), 'a redirect after the passkey'),
			login.url
		).toString()
	);
	expect(landed.response.status).toBe(200);
	return browser;
}

const PageProps = Type.Object({
	passkey: Type.Optional(
		Type.Object({
			options: Type.Object({
				challenge: Type.String(),
				rpId: Type.Optional(Type.String()),
				userVerification: Type.Optional(Type.String()),
				timeout: Type.Optional(Type.Number()),
				allowCredentials: Type.Optional(Type.Array(Type.Unknown()))
			}),
			remember: Type.Boolean()
		})
	)
});

/* The props a hydrated sign-in page carries for its script. */
export function propsIn(html: string): unknown {
	const raw = present(
		/window\.PROPS=(\{.*?\})<\/script>/.exec(html)?.[1],
		'the sign-in page’s props'
	);
	return JSON.parse(raw);
}

/* The passkey offer the sign-in page carries in its props, or undefined where it offers none. */
export function passkeyOfferIn(html: string) {
	return shaped(PageProps, propsIn(html)).passkey;
}

/* An authorization request of the project's client, opened in the browser; answers the sign-in page it lands on. */
export async function signInPage(
	browser: Browser,
	at: Project,
	parameters: Record<string, string> = {}
): Promise<{
	auth: AuthorizationRequest;
	url: string;
	html: string;
}> {
	const auth = new AuthorizationRequest({
		client_id: at.clientId,
		scope: 'openid',
		...parameters
	});
	const landed = await browser.open(
		`${at.origin}${at.prefix}/auth?${encodeParams(auth.params)}`
	);
	// 400 is the page with the attacker list's refusal in place of the password form (specs/125).
	expect([200, 400]).toContain(landed.response.status);
	expect(landed.url).toMatch(/\/ui\/[^/]+\/login(\?|$)/);
	return { auth, url: landed.url, html: await landed.response.text() };
}

/* The passkey door of the interaction a sign-in page (or the door's own re-render of it) belongs to. */
export function doorOf(pageUrl: string): string {
	const url = new URL(pageUrl);
	url.pathname = url.pathname.replace(/\/(login|passkey)$/, '/passkey');
	url.search = '';
	return url.toString();
}

/* Posts a `credential` field to the passkey door as it stands, for a case about what the door does with it. */
export function postCredential(
	browser: Browser,
	page: { url: string },
	credential: string,
	fields: Record<string, string> = {}
): Promise<Response> {
	return browser.post(doorOf(page.url), { credential, ...fields });
}

/*
 * Signs in with a passkey as the page's script does: the device answers the page's challenge, and the result is posted
 * to the passkey door with "Remember me" as the page has it — the checkbox's tick (`ticked`, ticked by default) where
 * the page has one, remembered where it has none. Answers the door's own answer, unfollowed.
 */
export async function postPasskey(
	browser: Browser,
	device: SoftAuthenticator,
	at: Project,
	page: { url: string; html: string },
	how: {
		ticked?: boolean;
		choices?: GetChoices;
		context?: Partial<BrowserContext>;
	} = {}
): Promise<Response> {
	const offer = present(passkeyOfferIn(page.html), 'a passkey offer');
	const assertion = await device.get(
		offer.options,
		{ origin: at.origin, ...how.context },
		how.choices
	);
	const remember = !offer.remember || how.ticked !== false;
	return postCredential(
		browser,
		page,
		JSON.stringify(assertion),
		remember ? { remember: 'on' } : {}
	);
}

/* The answer of a project's passkey door to `device`'s passkey in a fresh browser, as the page's script sends it. */
export async function presentedAt(
	at: Project,
	device: SoftAuthenticator,
	how: Parameters<typeof postPasskey>[4] = {}
): Promise<Response> {
	const browser = new Browser(at.origin);
	const page = await signInPage(browser, at);
	return postPasskey(browser, device, at, page, how);
}

/* A whole passkey sign-in through the project's client; answers the code its redirect URI receives. */
export async function signInWithPasskey(
	browser: Browser,
	device: SoftAuthenticator,
	at: Project,
	parameters: Record<string, string> = {}
): Promise<{ auth: AuthorizationRequest; code: string }> {
	const page = await signInPage(browser, at, parameters);
	const posted = await postPasskey(browser, device, at, page);
	return { auth: page.auth, code: await codeAfter(browser, posted, page.url) };
}

/* Follows the door's redirect to the client's redirect URI and answers the code it carries. */
export async function codeAfter(
	browser: Browser,
	posted: Response,
	from: string
): Promise<string> {
	const location = present(
		posted.headers.get('location'),
		`a redirect (answered ${String(posted.status)})`
	);
	const ended = await browser.open(new URL(location, from).toString());
	return present(
		new URL(ended.url).searchParams.get('code'),
		`a code (ended at ${ended.url})`
	);
}

const TokenAnswer = Type.Object({
	id_token: Type.String(),
	access_token: Type.String()
});

/* The code redeemed at the project's own token endpoint, as its public client does. */
export async function redeem(
	at: Project,
	auth: AuthorizationRequest,
	code: string,
	extra: Record<string, string> = {}
): Promise<{ id_token: string; access_token: string }> {
	const response = await elysia.handle(
		new Request(`${at.origin}${at.prefix}/token`, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({
				grant_type: 'authorization_code',
				client_id: at.clientId,
				code,
				code_verifier: auth.code_verifier,
				redirect_uri: present(auth.params.redirect_uri, 'a redirect URI'),
				...extra
			}).toString()
		})
	);
	expect(response.status).toBe(200);
	return shaped(TokenAnswer, await response.json());
}

/* What a signed token says. */
export function claimsOf(jwt: string): Record<string, unknown> {
	return decodeJWT(jwt).payload;
}

/* The newest mail to an address, with its words as a reader sees them. */
export function latestMail(address: string): { subject: string; text: string } {
	const mail = present(mailsTo(address).at(-1), `a mail to ${address}`);
	return { subject: mail.subject, text: mail.text };
}

/*
 * A passkey written straight to the store, for a case about what holding one means rather than about adding it: it
 * cannot sign in (its key is no key), and nothing reads it as one made through the page.
 */
export async function seedPasskey(
	bucketId: string,
	accountId: string,
	fields: Partial<Passkey> = {}
): Promise<Passkey> {
	const record: Passkey = {
		_id: Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString(
			'base64url'
		),
		bucketId,
		accountId,
		credentialId: Buffer.from(
			crypto.getRandomValues(new Uint8Array(16))
		).toString('base64url'),
		publicKey: 'cHVibGljLWtleQ',
		rpId: 'e.ly',
		counter: 0,
		backupEligible: true,
		backedUp: true,
		transports: ['internal'],
		aaguid: '00000000-0000-0000-0000-000000000000',
		createdAt: new Date(),
		createdVia: 'password_code',
		createdOn: { browser: 'chrome', system: 'windows' },
		...fields
	};
	expect(await getPasskeyStore().create(record)).toBe('created');
	return record;
}
