import { expect } from 'bun:test';
import { randomUUID } from 'node:crypto';

import {
	getBehindProxyAppStore,
	getPersonActivityStore
} from 'lib/adapters/index.ts';
import type { BehindProxyApp, PersonActivityRow } from 'lib/adapters/types.ts';
import { DEFAULT_BUCKET_ID } from 'lib/admin/consts.ts';
import { sessionCookieName } from 'lib/consts/param_list.ts';
import { getBucketStore } from 'lib/adapters/index.ts';
import epochTime from 'lib/helpers/epoch_time.ts';
import { Session } from 'lib/models/session.ts';
import { FRESH_SECONDS } from 'lib/totp/consts.ts';
import { present } from '../shape.ts';
import {
	Browser,
	defaultBucket,
	person,
	signInThroughPage,
	textOf,
	xsrfFrom
} from '../connected_apps/helpers.ts';

export { Browser, defaultBucket, person, textOf, xsrfFrom };

export const PAGE = '/account/sign-ins';
const DAY_MS = 86_400_000;

/* One successful sign-in as spec 133 records it; a case changes what it is about. */
export function signInRow(
	accountId: string,
	at: Date,
	overrides: Partial<PersonActivityRow> = {}
): PersonActivityRow {
	return {
		_id: randomUUID(),
		bucketId: DEFAULT_BUCKET_ID,
		accountId,
		day: at.toISOString().slice(0, 10),
		kind: 'signIn',
		outcome: 'let_in',
		reason: 'signed_in',
		place: { clientId: 'own-app' },
		method: 'password',
		device: { browser: 'chrome', system: 'windows' },
		count: 1,
		firstAt: at,
		lastAt: at,
		expiresAt: new Date(at.getTime() + 90 * DAY_MS),
		...overrides
	};
}

export async function seed(rows: PersonActivityRow[]): Promise<void> {
	const { failed } = await getPersonActivityStore().write(rows);
	expect(failed).toBe(0);
}

export function minutesAgo(minutes: number): Date {
	return new Date(Date.now() - minutes * 60_000);
}

/* The id of the browser's sign-in session: the raw value of its cookie at the root. */
export async function sessionIdOf(browser: Browser): Promise<string> {
	const bucket = present(
		await getBucketStore().find(DEFAULT_BUCKET_ID),
		'the default bucket'
	);
	const name = sessionCookieName(bucket);
	return present(
		browser.cookie
			.split('; ')
			.find((pair) => pair.startsWith(`${name}=`))
			?.slice(name.length + 1),
		'a session cookie'
	);
}

/* The browser's sign-in session record, read through its cookie as the page reads it. */
export async function sessionOf(browser: Browser): Promise<Session> {
	return present(
		await Session.tryFind(await sessionIdOf(browser)),
		'the session record'
	);
}

/* Changes how and when the browser's sign-in happened, as an older or a provider sign-in would have left it. */
export async function reshapeSession(
	browser: Browser,
	change: { ageSeconds?: number; amr?: string[] }
): Promise<Session> {
	const session = await sessionOf(browser);
	if (change.ageSeconds !== undefined) {
		session.payload.loginTs = epochTime() - change.ageSeconds;
	}
	if (change.amr !== undefined) session.payload.amr = change.amr;
	await session.save((session.payload.exp ?? 0) - epochTime());
	return session;
}

export const STALE = FRESH_SECONDS + 60;

/* A person signed in through the account page just now, as they would. */
export async function signedIn(): Promise<{
	browser: Browser;
	email: string;
	accountId: string;
}> {
	await defaultBucket();
	const { email, accountId } = await person();
	const browser = new Browser();
	const landed = await signInThroughPage(browser, email);
	expect(landed.status).toBe(200);
	return { browser, email, accountId };
}

export async function openPage(
	browser: Browser,
	query = '',
	prefix = ''
): Promise<{ response: Response; html: string }> {
	const response = await browser.request(`${prefix}${PAGE}${query}`);
	return { response, html: await response.text() };
}

/* The items of the list, as text, newest first. */
export function itemsOf(html: string): string[] {
	return [...html.matchAll(/<li[^>]*data-sign-in[^>]*>([\s\S]*?)<\/li>/g)].map(
		(m) => textOf(m[1])
	);
}

export async function appBehindProxy(
	name: string,
	address: string
): Promise<BehindProxyApp> {
	const now = new Date();
	return getBehindProxyAppStore().create({
		_id: randomUUID(),
		bucketId: DEFAULT_BUCKET_ID,
		name,
		address,
		proxyKind: 'caddy',
		rules: [],
		createdAt: now,
		updatedAt: now
	});
}
