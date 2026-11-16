import { Type, type Static } from '@sinclair/typebox';

import { encodeParams, bindClientToBucket } from '../test_helper.ts';
import { AuthorizationRequest } from '../AuthorizationRequest.ts';
import { Browser } from '../connected_apps/helpers.ts';
import { admin, type Reply } from '../provisioning/helpers.ts';
import { present, shaped } from '../shape.ts';
import { SECRET, codeFor } from '../amr/flow.ts';
import { getBucketStore, getUserStore } from 'lib/adapters/index.ts';
import { UNASSIGNED_GROUP_ID } from 'lib/admin/consts.ts';
import { setPeerResolverForTests } from 'lib/helpers/caller_address.ts';
import { flushPersonActivityNow } from 'lib/person_activity/flush.ts';
import nanoid from 'lib/helpers/nanoid.ts';

/*
 * A person's activity (specs/133) as an administrator meets it: a person signs in through the real screens, from an
 * address and a browser this file states, and the administrator reads what was recorded through the real admin
 * route, after the write the server makes once a minute.
 */

export const CLIENT = 'activity-app';
export const CODE_CLIENT = 'activity-billing';
export const PASSWORD = 'correct horse battery staple';
export const WRONG = 'not the password';
export const CHROME_ON_WINDOWS =
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

let peer: string | undefined;

/* Every request from now on comes from `address`; undefined for a request with no connection at all. */
export function from(address: string | undefined): void {
	peer = address;
	setPeerResolverForTests(() => peer);
}

/* A browser that sends the same `User-Agent` on every request, as a real one does. */
export class PersonBrowser extends Browser {
	constructor(private userAgent: string | null = CHROME_ON_WINDOWS) {
		super();
	}

	override request(path: string, init: RequestInit = {}): Promise<Response> {
		const headers = new Headers(init.headers);
		if (this.userAgent !== null && !headers.has('user-agent')) {
			headers.set('user-agent', this.userAgent);
		}
		return super.request(path, { ...init, headers });
	}
}

let hash: string | undefined;

export async function project(
	fields: Record<string, unknown> = {}
): Promise<string> {
	const bucket = await getBucketStore().create({
		_id: `activity-${nanoid()
			.toLowerCase()
			.replace(/[^a-z0-9]/g, '')}`,
		name: 'Acme people',
		ownerGroupId: UNASSIGNED_GROUP_ID,
		...fields
	});
	await bindClientToBucket(CLIENT, bucket._id);
	await bindClientToBucket(CODE_CLIENT, bucket._id);
	return bucket._id;
}

export async function person(
	bucketId: string,
	options: { code?: boolean } = {}
): Promise<{ email: string; accountId: string }> {
	hash ??= await Bun.password.hash(PASSWORD);
	const email = `person-${Math.random().toString(36).slice(2)}@acme.test`;
	const user = await getUserStore(bucketId).create(email, hash, true);
	if (options.code) {
		await getUserStore(bucketId).update(user._id, {
			totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0 }
		});
	}
	return { email, accountId: user._id };
}

/* Opens the application signed out: the browser lands on the login page. */
export async function openLogin(
	browser: Browser,
	clientId = CLIENT
): Promise<string> {
	const auth = new AuthorizationRequest({
		client_id: clientId,
		scope: 'openid'
	});
	const { url } = await browser.open(
		`/auth?${encodeParams(auth.params).toString()}`
	);
	if (!/\/ui\/[^/]+\/login$/.test(url)) {
		throw new Error(`expected the login page, landed on ${url}`);
	}
	return url;
}

/* Types an email and password on a fresh login page; answers where the browser landed. */
export async function typePassword(
	browser: Browser,
	email: string,
	password = PASSWORD,
	clientId = CLIENT
): Promise<{ response: Response; url: string }> {
	const login = await openLogin(browser, clientId);
	const posted = await browser.post(login, { username: email, password });
	const location = posted.headers.get('location');
	if (location === null) return { response: posted, url: login };
	return browser.open(new URL(location, login).toString());
}

/* Types the code (right or wrong) on the code page a password sign-in reached. */
export async function typeCode(
	browser: Browser,
	codeUrl: string,
	code = codeFor()
): Promise<{ response: Response; url: string }> {
	const posted = await browser.post(codeUrl, { code });
	const location = posted.headers.get('location');
	if (location === null) return { response: posted, url: codeUrl };
	return browser.open(new URL(location, codeUrl).toString());
}

/* A whole password sign-in that lands back at the application. */
export async function signIn(
	email: string,
	browser: Browser = new PersonBrowser()
): Promise<void> {
	const landed = await typePassword(browser, email);
	if (!landed.url.startsWith('http://e.ly/activity/callback')) {
		throw new Error(
			`the sign-in should return to the app, landed on ${landed.url}`
		);
	}
}

export const RowView = Type.Object({
	id: Type.String(),
	day: Type.String(),
	kind: Type.String(),
	outcome: Type.String(),
	reason: Type.String(),
	words: Type.Object({
		outcome: Type.String(),
		reason: Type.String(),
		sawText: Type.Union([Type.String(), Type.Null()]),
		method: Type.Union([Type.String(), Type.Null()]),
		device: Type.Union([Type.String(), Type.Null()])
	}),
	place: Type.Record(Type.String(), Type.Union([Type.String(), Type.Null()])),
	client: Type.Union([Type.String(), Type.Null()]),
	address: Type.Union([Type.String(), Type.Null()]),
	addressFrom: Type.Union([Type.String(), Type.Null()]),
	facts: Type.Union([
		Type.Null(),
		Type.Object({
			country: Type.Union([Type.String(), Type.Null()]),
			categories: Type.Array(Type.String())
		})
	]),
	newAddress: Type.Boolean(),
	count: Type.Number(),
	firstAt: Type.String(),
	lastAt: Type.String(),
	check: Type.Union([
		Type.Null(),
		Type.Object({ app: Type.String() }),
		Type.Object({ api: Type.String() })
	])
});
export type RowView = Static<typeof RowView>;

export const PageView = Type.Object({
	recording: Type.Boolean(),
	recordingBegan: Type.Union([Type.String(), Type.Null()]),
	keptDays: Type.Number(),
	rows: Type.Array(RowView),
	next: Type.Union([Type.String(), Type.Null()]),
	busyDays: Type.Array(Type.String())
});
export type PageView = Static<typeof PageView>;

export function activityPath(bucketId: string, accountId: string): string {
	return `/admin/api/projects/${encodeURIComponent(bucketId)}/users/${encodeURIComponent(accountId)}/activity`;
}

export async function readActivity(
	cookie: string,
	bucketId: string,
	accountId: string,
	body: Record<string, unknown> = {}
): Promise<Reply> {
	return admin('POST', activityPath(bucketId, accountId), cookie, body);
}

/* What the administrator reads once the server has written what it held. */
export async function activityOf(
	cookie: string,
	bucketId: string,
	accountId: string,
	body: Record<string, unknown> = {}
): Promise<PageView> {
	await flushPersonActivityNow();
	const reply = await readActivity(cookie, bucketId, accountId, body);
	if (reply.status !== 200) {
		throw new Error(
			`reading the activity answered ${String(reply.status)}: ${JSON.stringify(reply.body)}`
		);
	}
	return shaped(PageView, reply.body);
}

export function only<T>(rows: readonly T[], what: string): T {
	if (rows.length !== 1) {
		throw new Error(`expected one ${what}, found ${String(rows.length)}`);
	}
	return present(rows[0], what);
}

export { codeFor, SECRET };
