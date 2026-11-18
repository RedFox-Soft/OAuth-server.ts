import crypto from 'node:crypto';

import type { UserBucket } from '../adapters/types.js';
import { accountPageBase } from '../account_page/client.js';
import { routeNames } from '../consts/param_list.js';
import { DISOWN_TTL_SECONDS } from '../totp/consts.js';
import { checkedAdapter } from '../adapters/index.js';
import { digestOf } from '../totp/self_service.js';
import { TotpLinkPayload } from '../totp/types.js';
import epochTime from '../helpers/epoch_time.js';

/*
 * The "This wasn't me" link of an email about a new sign-in (specs/138 research R4): spec 126's link store and rules,
 * with a purpose of its own. The token exists only in the email; the store keeps its digest. It lives as long as a
 * "This was not me" about a factor, works once, and goes with the account's access, so after any sign-out everywhere
 * it has nothing left to end and says so.
 */

function links() {
	return checkedAdapter('TotpLink', TotpLinkPayload);
}

export async function issueNotMeLink(
	bucket: UserBucket,
	accountId: string,
	signInId: string
): Promise<string> {
	const token = crypto.randomBytes(32).toString('base64url');
	await links().upsert(
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
): Promise<TotpLinkPayload | undefined> {
	if (!token) return undefined;
	const record = await links().find(digestOf(token));
	return record?.purpose === 'notme' && record.exp > epochTime()
		? record
		: undefined;
}

/* Spends the link; of two racing confirmations exactly one is told yes. */
export async function spendNotMeLink(token: string): Promise<boolean> {
	return token ? links().consume(digestOf(token)) : false;
}
