import { expect } from 'bun:test';
import { elysia } from 'lib/index.ts';
import { ISSUER } from 'lib/configs/env.js';
import type { ConsentView } from 'lib/interactions/consentView.js';
import { AuthorizationRequest } from 'test/AuthorizationRequest.js';
import { visible } from '../page_text.js';
import { shownAccount } from '../consent_form.js';

type Params = ConstructorParameters<typeof AuthorizationRequest>[0];

/* The jar a browser would hold after `response`: what it had, plus what the response set. */
export function withCookies(cookie: string, response: Response): string {
	const jar = new Map<string, string>();
	for (const pair of cookie.split('; ').filter(Boolean)) {
		const eq = pair.indexOf('=');
		if (eq > 0) jar.set(pair.slice(0, eq), pair.slice(eq + 1));
	}
	for (const raw of response.headers.getSetCookie()) {
		const [pair] = raw.split(';');
		const eq = pair.indexOf('=');
		if (eq <= 0) continue;
		const name = pair.slice(0, eq);
		const value = pair.slice(eq + 1);
		if (raw.includes('Thu, 01 Jan 1970') || !value) jar.delete(name);
		else jar.set(name, value);
	}
	return [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
}

/* The props the page hydrates from — everything it shows, as the server worked it out. */
function propsOf(html: string): ConsentView {
	const json = /window\.PROPS=(.*?)<\/script>/s.exec(html)?.[1];
	if (!json) throw new Error('the consent page carried no props');
	return JSON.parse(json) as ConsentView;
}

export interface ConsentPage {
	uid: string;
	cookie: string;
	html: string;
	/* What a reader sees, markup removed. */
	text: string;
	view: ConsentView;
	/* The page's response, for its headers. */
	response: Response;
}

/* Starts an authorization request with a signed-in session and opens the consent page it leads to. */
export async function openConsent(
	params: Params,
	cookie: string
): Promise<ConsentPage> {
	const auth = new AuthorizationRequest(params);
	const started = await auth.authorize({ headers: { cookie } });
	expect(started.status).toBe(303);
	const location = started.headers.get('location') ?? '';
	expect(location).toMatch(/^\/ui\/[^/]+\/consent$/);
	const uid = location.split('/')[2];
	const jar = withCookies(cookie, started);

	const response = await elysia.handle(
		new Request(`${ISSUER}/ui/${uid}/consent`, { headers: { cookie: jar } })
	);
	expect(response.status).toBe(200);
	const html = await response.clone().text();
	return {
		uid,
		cookie: jar,
		html,
		text: visible(html),
		view: propsOf(html),
		response
	};
}

/* Submits the consent form as the page's own form would, or with the account a caller supplies. */
export async function decide(
	page: Pick<ConsentPage, 'uid' | 'cookie'>,
	action: 'allow' | 'cancel',
	accountId?: string
): Promise<Response> {
	const fields: Record<string, string> = { action };
	const account = accountId ?? (await shownAccount(page.uid));
	if (account !== '') fields.accountId = account;
	return elysia.handle(
		new Request(`${ISSUER}/ui/${page.uid}/consent`, {
			method: 'POST',
			headers: {
				cookie: page.cookie,
				'content-type': 'application/x-www-form-urlencoded'
			},
			body: new URLSearchParams(fields).toString()
		})
	);
}
