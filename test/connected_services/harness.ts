import { expect } from 'bun:test';

import { ISSUER } from 'lib/configs/env.js';
import { elysia } from 'lib/index.ts';
import {
	getBucketStore,
	getConnectedAccountStore,
	rawConnectedAccountStoreForTests
} from 'lib/adapters/index.ts';
import { connectedAccountId } from 'lib/connected_services/accounts.ts';
import type { UserBucket } from 'lib/adapters/types.ts';
import type {
	ConnectedAccount,
	ConnectedService
} from 'lib/connected_services/types.ts';
import { present } from '../shape.ts';
import { createAdministrator } from '../administrators.ts';
import { personalGroupId } from '../admin_session.ts';
import { cookieFor } from '../admin/ownership_fixtures.ts';
import {
	Browser,
	defaultBucket,
	person,
	signInThroughPage,
	textOf,
	xsrfFrom
} from '../connected_apps/helpers.ts';
import { unique } from './stubs.ts';

/*
 * A person on their connected-services page (specs/117), driven through the real routes as a browser would:
 * signed in through the account page, a confirmation opened, its form posted, the provider's answer delivered
 * to the callback. Providers are stubs (stubs.ts); nothing reaches the network.
 */

export const PAGE = '/account/services';
export const CALLBACK = `${ISSUER}/account/services/callback`;

export interface Person {
	browser: Browser;
	accountId: string;
	email: string;
	bucket: UserBucket;
}

export async function signedInPerson(): Promise<Person> {
	const bucket = await defaultBucket();
	const { email, accountId } = await person(bucket._id);
	const browser = new Browser();
	await signInThroughPage(browser, email);
	return { browser, accountId, email, bucket };
}

/* A service on the default bucket, declared as the admin route stores one. */
export async function addService(
	overrides: Partial<ConnectedService> & Pick<ConnectedService, 'kind'>,
	bucketId?: string
): Promise<ConnectedService> {
	const bucket = bucketId
		? present(await getBucketStore().find(bucketId), 'the project')
		: await defaultBucket();
	const now = new Date().toISOString();
	const service: ConnectedService = {
		id: unique('svc'),
		clientId: unique('client'),
		clientSecret: unique('secret'),
		scopes: [],
		displayName: 'Service',
		createdAt: now,
		updatedAt: now,
		...overrides
	};
	await getBucketStore().update(bucket._id, {
		connectedServices: [...(bucket.connectedServices ?? []), service]
	});
	return service;
}

/* Opens the connect confirmation and posts it; answers the server's response (a redirect to the provider). */
export async function postConnect(
	browser: Browser,
	serviceId: string,
	headers: Record<string, string> = {}
): Promise<Response> {
	const page = await browser.request(
		`${PAGE}?connect=${encodeURIComponent(serviceId)}`
	);
	const html = await page.text();
	return browser.post(
		PAGE,
		{ action: 'connect', serviceId, xsrf: xsrfFrom(html) },
		headers
	);
}

/* The provider address the server sent the person to, after a connect that was let through. */
export async function startConnect(
	browser: Browser,
	serviceId: string
): Promise<URL> {
	const response = await postConnect(browser, serviceId);
	expect(response.status).toBe(303);
	return new URL(
		present(response.headers.get('location'), 'a provider address')
	);
}

/* The provider sends the person back with a code (or an error), to whichever browser `browser` is. */
export async function callback(
	browser: Browser,
	authorizeUrl: URL,
	answer: Record<string, string> = { code: unique('code') }
): Promise<Response> {
	const params = new URLSearchParams({
		state: present(authorizeUrl.searchParams.get('state'), 'a state'),
		...answer
	});
	return browser.request(`${CALLBACK}?${params.toString()}`);
}

/* Follows the callback's redirect back to the page and answers what the person reads there. */
export async function landed(
	browser: Browser,
	response: Response
): Promise<string> {
	expect(response.status).toBe(303);
	const location = present(response.headers.get('location'), 'the page');
	const page = await browser.request(new URL(location, ISSUER).toString());
	expect(page.status).toBe(200);
	return textOf(await page.text());
}

export async function accountsOf(
	accountId: string
): Promise<ConnectedAccount[]> {
	const bucket = await defaultBucket();
	return rawConnectedAccountStoreForTests().listByAccount(
		bucket._id,
		accountId
	);
}

// ---------------------------------------------------------------- the administrative surface

/* An administrator of their own project, signed in to the console. */
export async function projectAdministrator(): Promise<{
	cookie: string;
	bucket: UserBucket;
}> {
	const user = await createAdministrator('plain');
	const cookie = await cookieFor(user);
	const bucket = await getBucketStore().create({
		name: unique('project'),
		ownerGroupId: await personalGroupId(user._id)
	});
	return { cookie, bucket };
}

export async function admin(
	cookie: string,
	method: string,
	path: string,
	body?: unknown
): Promise<{ status: number; json: Record<string, unknown> }> {
	const response = await elysia.handle(
		new Request(`${ISSUER}${path}`, {
			method,
			headers: {
				cookie,
				...(body === undefined ? {} : { 'content-type': 'application/json' })
			},
			...(body === undefined ? {} : { body: JSON.stringify(body) })
		})
	);
	const text = await response.text();
	return {
		status: response.status,
		json: text ? (JSON.parse(text) as Record<string, unknown>) : {}
	};
}

/* An account as a connect would have stored it, written straight to the store, for cases about what comes after. */
export async function seededAccount(
	who: { accountId: string; bucket: UserBucket },
	service: ConnectedService,
	fields: Partial<ConnectedAccount> = {}
): Promise<ConnectedAccount> {
	const upstreamId = fields.upstreamId ?? unique('upstream');
	const now = new Date().toISOString();
	const record: ConnectedAccount = {
		_id: connectedAccountId(
			who.bucket._id,
			service.id,
			who.accountId,
			upstreamId
		),
		bucketId: who.bucket._id,
		serviceId: service.id,
		accountId: who.accountId,
		upstreamId,
		label: unique('label'),
		accessToken: unique('access'),
		refreshToken: unique('refresh'),
		tokenType: 'Bearer',
		scopes: service.scopes,
		scopesInferred: false,
		connectedAt: now,
		updatedAt: now,
		...fields
	};
	await getConnectedAccountStore().put(record);
	return record;
}

/* Opens the disconnect confirmation and posts it, as the person would. */
export async function postDisconnect(
	browser: Browser,
	connectedAccount: string
): Promise<Response> {
	const page = await browser.request(
		`${PAGE}?disconnect=${encodeURIComponent(connectedAccount)}`
	);
	return browser.post(PAGE, {
		action: 'disconnect',
		connectedAccountId: connectedAccount,
		xsrf: xsrfFrom(await page.text())
	});
}
