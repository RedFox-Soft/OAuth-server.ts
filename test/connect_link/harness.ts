import { expect, spyOn } from 'bun:test';
import { Type } from '@sinclair/typebox';

import { ISSUER } from 'lib/configs/env.js';
import { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { ConnectedService } from 'lib/connected_services/types.ts';
import { getUserStore } from 'lib/adapters/index.ts';
import { present, shaped } from '../shape.js';
import { seedAccount, type Setup } from '../test_helper.js';
import {
	PASSWORD,
	textOf,
	xsrfFrom,
	type Browser
} from '../connected_apps/helpers.ts';
import { signedInPerson, type Person } from '../connected_services/harness.ts';
import { exchange, signIn, type SignedIn } from '../upstream_tokens/harness.ts';

/*
 * An agent's connect link (specs/119), driven end to end: the agent's exchange is refused with a link, the person
 * opens it in their browser on the account page's own routes, and the agent tries again. The exchange and the
 * person are 118's and 117's helpers; only what the link adds lives here.
 */

export const LinkRefusal = Type.Object({
	error: Type.String(),
	error_description: Type.Optional(Type.String()),
	reason: Type.Optional(Type.String()),
	connect_uri: Type.Optional(Type.String()),
	connect_id: Type.Optional(Type.String()),
	connect_expires_in: Type.Optional(Type.Number()),
	connect_message: Type.Optional(Type.String()),
	accounts: Type.Optional(Type.Array(Type.String()))
});

type Answer = Awaited<ReturnType<typeof exchange>>;

export function refusedWith(answer: Answer, status = 400) {
	if (answer.status !== status) {
		throw new Error(
			`expected a ${String(status)} refusal, got ${String(answer.status)} ${JSON.stringify(answer.data)}`
		);
	}
	return shaped(LinkRefusal, answer.error?.value);
}

/*
 * A person signed in to their account page, and to the agent; answers both. The agent's sign-in skips its prompts
 * as 118's specs do, and only it: the link's own sign-in must ask for a password like any other.
 */
export async function personAndAgent(
	setup: Setup,
	clientId = 'agent'
): Promise<Person & { signedIn: SignedIn }> {
	const person = await signedInPerson();
	const store = getUserStore(person.bucket._id);
	const { _id, ...stored } = present(
		await store.find(person.accountId),
		'the person'
	);
	const prompts = spyOn(OIDCContext.prototype, 'promptPending').mockReturnValue(
		false
	);
	try {
		const signedIn = await signIn(setup, clientId, person.accountId);
		return { ...person, signedIn };
	} finally {
		prompts.mockRestore();
		/* The harness's sign-in seeds the account afresh, without the password the link's own sign-in needs. */
		seedAccount(_id, stored, person.bucket._id);
	}
}

/* The exchange the agent makes, refused; answers the refusal and the link's path on this server. */
export async function linkFor(
	signedIn: SignedIn,
	service: ConnectedService,
	fields: { loginHint?: string; scope?: string } = {}
): Promise<{ body: ReturnType<typeof refusedWith>; path: string }> {
	const body = refusedWith(
		await exchange({
			subjectToken: signedIn.accessToken,
			audience: service.id,
			...fields
		})
	);
	const uri = present(body.connect_uri, 'a connect link');
	return { body, path: new URL(uri).pathname };
}

/* Opens the link and answers the page the person reads, after following any redirect on this server. */
export async function read(
	browser: Browser,
	path: string
): Promise<{ status: number; text: string; html: string; url: string }> {
	const { response, url } = await browser.open(path);
	const html = await response.text();
	return { status: response.status, text: textOf(html), html, url };
}

/* Posts the link's form as the page served it. */
export async function act(
	browser: Browser,
	path: string,
	fields: Record<string, string | string[]>,
	headers: Record<string, string> = {}
): Promise<Response> {
	const html = await (await browser.request(path)).text();
	const body = new URLSearchParams({ xsrf: xsrfFrom(html) });
	for (const [name, value] of Object.entries(fields)) {
		for (const one of Array.isArray(value) ? value : [value])
			body.append(name, one);
	}
	return browser.request(path, {
		method: 'POST',
		headers: {
			'content-type': 'application/x-www-form-urlencoded',
			...headers
		},
		body: body.toString()
	});
}

/* Signs in on the login page a link sent the browser to, and follows back to wherever that leads. */
export async function signInFrom(
	browser: Browser,
	path: string,
	email: string
): Promise<{ status: number; text: string; url: string }> {
	const login = await browser.open(path);
	expect(login.url).toMatch(/\/ui\/[^/]+\/login$/);
	const posted = await browser.request(login.url, {
		method: 'POST',
		headers: { 'content-type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			username: email,
			password: PASSWORD
		}).toString()
	});
	const location = present(posted.headers.get('location'), 'a resume');
	const landed = await browser.open(new URL(location, login.url).toString());
	return {
		status: landed.response.status,
		text: textOf(await landed.response.text()),
		url: landed.url
	};
}

/* Where a redirect sends the browser, as a URL. */
export function locationOf(response: Response): URL {
	return new URL(
		present(response.headers.get('location'), 'a location'),
		ISSUER
	);
}
