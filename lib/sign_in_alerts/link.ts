import crypto from 'node:crypto';

import type { UserBucket } from '../adapters/types.js';
import { accountPageBase } from '../account_page/client.js';
import { routeNames } from '../consts/param_list.js';
import { DISOWN_TTL_SECONDS } from '../totp/consts.js';
import { checkedAdapter } from '../adapters/index.js';
import { digestOf } from '../totp/self_service.js';
import { NotMeLinkPayload } from '../totp/types.js';
import epochTime from '../helpers/epoch_time.js';

/*
 * The "This wasn't me" link of an email about a new sign-in (specs/138 research R4): spec 126's rules for such a link,
 * with a purpose of its own. The token exists only in the email; the store keeps its digest. It lives as long as a
 * "This wasn't me" about a factor, works once, and outlives every sign-out everywhere: whoever signed in from
 * somewhere new can press that button too, and the owner still needs the password reset this link sends.
 */

function notMeLinks() {
	return checkedAdapter('NotMeLink', NotMeLinkPayload);
}

export async function issueNotMeLink(
	bucket: UserBucket,
	accountId: string,
	signInId: string
): Promise<string> {
	const token = crypto.randomBytes(32).toString('base64url');
	await notMeLinks().upsert(
		digestOf(token),
		{
			accountId,
			bucketId: bucket._id,
			purpose: 'notme',
			signInId,
			exp: epochTime() + DISOWN_TTL_SECONDS
		},
		DISOWN_TTL_SECONDS
	);
	return `${accountPageBase(bucket)}${routeNames.account_not_me}?token=${encodeURIComponent(token)}`;
}

/*
 * A live link of this purpose, read without spending it. Whether it may act where it was opened is the page's
 * question (`acceptsAt`), never answered here.
 */
export async function readNotMeLink(
	token: string
): Promise<NotMeLinkPayload | undefined> {
	if (!token) return undefined;
	const record = await notMeLinks().find(digestOf(token));
	return record?.purpose === 'notme' && record.exp > epochTime()
		? record
		: undefined;
}

/* Spends the link; of two racing confirmations exactly one is told yes. */
export async function spendNotMeLink(token: string): Promise<boolean> {
	return token ? notMeLinks().consume(digestOf(token)) : false;
}
