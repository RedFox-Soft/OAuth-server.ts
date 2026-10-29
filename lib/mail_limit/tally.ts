import { checkedAdapter } from '../adapters/index.js';
import { ApplicationConfig } from '../configs/application.js';
import { callerAddressOf } from '../helpers/caller_address.js';
import { noteAttack } from '../attack_reports/tally.js';
import epochTime from '../helpers/epoch_time.js';
import { MailRequestTallyPayload } from './types.js';

const HOUR = 60 * 60;

function tallies() {
	return checkedAdapter('MailRequestTally', MailRequestTallyPayload);
}

export type MailAdmission =
	| { readonly admitted: true }
	| { readonly admitted: false; readonly retryAfter: number };

/*
 * Whether this request may make the instance send mail to an address its caller names (specs/115,
 * `mail.requestsPerCallerPerHour`). Called first in each such route, before any lookup, so every request
 * counts whatever it would have found — which is what keeps a refusal from saying anything about which
 * addresses have accounts.
 *
 * Counted, then compared: the request whose own number is past the limit is refused, so a burst of
 * parallel requests cannot all read the count before any of them adds to it (the lesson the login
 * throttle learned, lib/login_throttle/throttle.ts). A fixed UTC hour rather than a sliding window: the
 * bound is "per hour", and a caller timing requests at the boundary gains one hour's allowance at most.
 *
 * A request with no address — one the server dispatched to itself — is not counted: none reaches a mail
 * route in a running server, and counting them together would only make every in-process caller share
 * one allowance.
 */
export async function admitMailRequest(
	request: Request
): Promise<MailAdmission> {
	// Every mail request is reported past its threshold, admitted or not (specs/114).
	noteAttack(request, 'mail_requests');
	const caller = callerAddressOf(request);
	if (caller.from === 'unattributed') return { admitted: true };

	const now = epochTime();
	const hourStart = now - (now % HOUR);
	const ends = hourStart + HOUR;
	// Kept an hour past its own: a record that vanished at the boundary could be re-created by a late write.
	const keep = ends + HOUR - now;
	const key = `${caller.address}:${String(hourStart)}`;

	await tallies().create(key, { count: 0, exp: now + keep }, keep);
	const count = (await tallies().increment(key, 'count')) ?? 1;
	return count > ApplicationConfig['mail.requestsPerCallerPerHour']
		? { admitted: false, retryAfter: ends - now }
		: { admitted: true };
}

/*
 * A page answered as a refusal: the same document, with 429 and the seconds until the hour turns. The
 * page itself is the form the visitor was on, so they keep their place and read why.
 */
export async function mailLimitedResponse(
	page: Response | Promise<Response>,
	retryAfter: number
): Promise<Response> {
	const rendered = await page;
	const headers = new Headers(rendered.headers);
	headers.set('retry-after', String(retryAfter));
	return new Response(rendered.body, { status: 429, headers });
}
