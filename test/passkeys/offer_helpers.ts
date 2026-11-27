import { expect } from 'bun:test';
import { Type } from '@sinclair/typebox';

import { getUserStore } from 'lib/adapters/index.ts';
import { present, shaped } from '../shape.ts';
import { codeFor } from '../two_step_page/helpers.ts';
import type { AuthorizationRequest } from '../AuthorizationRequest.ts';
import type { CreateChoices, SoftAuthenticator } from './authenticator.ts';
import {
	Browser,
	CHROME_ON_WINDOWS,
	PASSWORD,
	codeAfter,
	propsIn,
	signInPage,
	type Project
} from './helpers.ts';

/*
 * The passkey offer after a password sign-in (specs/141), driven the way a browser drives it: the sign-in page's form
 * with the device report and "Remember me" as the page's script and checkbox leave them, the code step where one is
 * asked, then wherever the sign-in lands.
 */

export const SECRET = 'JBSWY3DPEHPK3PXP';

/* Gives the person an authenticator app, so their password sign-in is followed by the code step. */
export async function holdsCode(at: Project, accountId: string): Promise<void> {
	await getUserStore(at.bucketId).update(accountId, {
		totp: { secret: SECRET, enrolledAt: new Date(), lastStep: 0, via: 'self' }
	});
}

export interface Landed {
	browser: Browser;
	auth: AuthorizationRequest;
	/* Where the sign-in stopped: the offer page, another page of the sign-in, or the app's redirect URI. */
	url: string;
	response: Response;
}

/*
 * A password sign-in through the project's client. `device` is what the page's script reports (true: this device can
 * make a passkey), `remember` the checkbox; a person holding a code is asked it and answers it.
 */
export async function passwordSignIn(
	at: Project,
	email: string,
	how: {
		device?: boolean;
		remember?: boolean;
		browser?: Browser;
		parameters?: Record<string, string>;
	} = {}
): Promise<Landed> {
	const browser = how.browser ?? new Browser(at.origin);
	const page = await signInPage(browser, at, how.parameters);
	const posted = await browser.post(page.url, {
		username: email,
		password: PASSWORD,
		...(how.remember === false ? {} : { remember: 'on' }),
		...(how.device === false ? {} : { passkeyDevice: '1' })
	});
	let answer = posted;
	let from = page.url;
	const location = present(posted.headers.get('location'), 'a redirect');
	if (/\/totp$/.test(location)) {
		from = new URL(location, page.url).toString();
		answer = await browser.post(from, { code: codeFor(SECRET) });
	}
	const landed = await browser.open(
		new URL(
			present(answer.headers.get('location'), 'a redirect'),
			from
		).toString()
	);
	return { browser, auth: page.auth, ...landed };
}

/* Whether a sign-in stopped at the offer. */
export function atOffer(landed: { url: string }): boolean {
	return /\/ui\/[^/]+\/passkey-offer$/.test(landed.url);
}

const OfferProps = Type.Object({
	state: Type.Union([Type.Literal('offer'), Type.Literal('created')]),
	email: Type.String(),
	options: Type.Optional(
		Type.Object({
			challenge: Type.String(),
			rp: Type.Object({
				id: Type.Optional(Type.String()),
				name: Type.String()
			}),
			user: Type.Object({
				id: Type.String(),
				name: Type.String(),
				displayName: Type.String()
			})
		})
	),
	silent: Type.Optional(Type.Boolean()),
	askNever: Type.Optional(Type.Boolean()),
	conditional: Type.Optional(Type.Boolean()),
	refused: Type.Optional(Type.String()),
	campaign: Type.Optional(
		Type.Object({
			canSkip: Type.Boolean(),
			skipsLeft: Type.Number(),
			maxSkips: Type.Number()
		})
	)
});

/* What the offer page carries for its script. */
export function offerIn(html: string) {
	return shaped(OfferProps, propsIn(html));
}

/*
 * Creates the passkey at the offer the browser stands at, as the page's script does: the device answers the page's
 * options and the answer is posted, `silent` as the browser's silent creation posts it. Answers the page's answer.
 */
export async function createAtOffer(
	at: Project,
	landed: Landed,
	device: SoftAuthenticator,
	{
		silent = false,
		choices = {}
	}: { silent?: boolean; choices?: CreateChoices } = {}
): Promise<Response> {
	const offer = offerIn(await landed.response.clone().text());
	const options = present(offer.options, 'the offer’s creation options');
	const made = await device.create(options, { origin: at.origin }, choices);
	return landed.browser.post(
		landed.url,
		{
			action: 'create',
			credential: JSON.stringify(made),
			...(silent ? { silent: '1' } : {})
		},
		{ 'user-agent': CHROME_ON_WINDOWS }
	);
}

/* An answer of the offer page's own forms ("Not now", "Don't ask again", "Continue"), followed to the app's code. */
export async function leaveOffer(
	landed: Landed,
	action: 'not_now' | 'never' | 'continue'
): Promise<string> {
	const posted = await landed.browser.post(landed.url, { action });
	expect(posted.status).toBe(303);
	return codeAfter(landed.browser, posted, landed.url);
}
