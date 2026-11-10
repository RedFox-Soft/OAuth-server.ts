import crypto from 'node:crypto';

import {
	checkedAdapter,
	getBucketStore,
	getUserStore
} from '../adapters/index.js';
import type { User, UserBucket } from '../adapters/types.js';
import { accountPageBase } from '../account_page/client.js';
import { recordEndUserAudit } from '../admin/audit/record.js';
import { configuration } from '../configs/application.js';
import type { RequestBucket } from '../configs/issuer.js';
import { AMR_FOR_DISTINCTION } from '../consts/amr.js';
import { routeNames } from '../consts/param_list.js';
import {
	EndUserError,
	enrolOwnAuthenticator,
	enrolmentInstant
} from '../end_users/service.js';
import epochTime from '../helpers/epoch_time.js';
import { nextRateFields, rateRefusal } from '../helpers/rate_window.js';
import { emailLanguage } from '../i18n/resolve.js';
import { admitMailRequest } from '../mail_limit/tally.js';
import { deliver, mailDeliveryConfigured } from '../mail/mailer.js';
import {
	twoStepLinkEmail,
	twoStepNoticeEmail,
	type TwoStepLink,
	type TwoStepNotice
} from '../mail/templates/two_step.js';
import type { Session } from '../models/session.js';
import {
	DISOWN_TTL_SECONDS,
	FRESH_SECONDS,
	LINK_COOLDOWN_SECONDS,
	LINK_DAILY_CAP,
	LINK_TTL_SECONDS,
	LINK_WINDOW_SECONDS
} from './consts.js';
import type { Proved } from './enrollment.js';
import { TotpLinkPayload, TotpLinkThrottlePayload } from './types.js';

/*
 * A person's own two-step verification (specs/126): who may start or change it, the links mailed to prove the
 * mailbox, the notices about every change, and the session an enrolment raises. The page (lib/account_page/) and the
 * sign-in (lib/interactions/) decide when; every write to the person is lib/end_users/service.ts's.
 */

function links() {
	return checkedAdapter('TotpLink', TotpLinkPayload);
}

function linkCounts() {
	return checkedAdapter('TotpLinkThrottle', TotpLinkThrottlePayload);
}

const LINK_BOUNDS = {
	cooldownSeconds: LINK_COOLDOWN_SECONDS,
	cap: LINK_DAILY_CAP,
	windowSeconds: LINK_WINDOW_SECONDS
};

const digestOf = (token: string) =>
	crypto.createHash('sha256').update(token).digest('hex');

/* The holder of an enrolment started on the person's page: their browser's sign-in session. */
export function pageHolder(session: Session): string {
	return `account:${session.payload.uid}`;
}

/*
 * The person entered their password in this browser no more than fifteen minutes ago (research R3). A sign-in through
 * a provider is not one: whoever holds the provider account may hold the mailbox too.
 */
export function freshPassword(session: Session): boolean {
	const { amr, loginTs } = session.payload;
	return (
		Array.isArray(amr) &&
		amr.includes('pwd') &&
		typeof loginTs === 'number' &&
		epochTime() - loginTs <= FRESH_SECONDS
	);
}

/* The person entered a code from their authenticator app in this browser no more than fifteen minutes ago. */
export function freshCode(session: Session): boolean {
	const { acr, amr, loginTs } = session.payload;
	return (
		acr === configuration.acrMap.multi_factor &&
		Array.isArray(amr) &&
		amr.includes('otp') &&
		typeof loginTs === 'number' &&
		epochTime() - loginTs <= FRESH_SECONDS
	);
}

export type SelfService = 'on' | 'off' | 'no_password_login' | 'no_mail';

/*
 * Whether people of this project can set up a factor themselves right now. Absent means on; it takes password sign-in,
 * which is all a factor protects, and mail, which is how an enrolment is proved.
 */
export async function selfServiceState(
	bucket: UserBucket
): Promise<SelfService> {
	if (bucket.totpSelfService === false) return 'off';
	if (!bucket.passwordLogin) return 'no_password_login';
	if (!(await mailDeliveryConfigured())) return 'no_mail';
	return 'on';
}

function who(bucket: UserBucket, user: User) {
	return { service: bucket.displayName ?? bucket.name, email: user.email };
}

export function securityPageUrl(bucket: RequestBucket): string {
	return `${accountPageBase(bucket)}${routeNames.account_security}`;
}

export type LinkSent = 'sent' | 'throttled' | 'mail_failed';

/*
 * Mails a link that proves the mailbox, bound to `holder`. One a minute and five a day per account, and under the
 * instance's per-caller mail limit too (spec 115). The newest link of the account is the only one that works, so a
 * resend or a new start kills every earlier one.
 */
export async function sendLink(
	bucket: UserBucket,
	user: User,
	purpose: TwoStepLink,
	holder: string,
	options: {
		request: Request;
		urlFor: (token: string) => string;
		enrolledAt?: number;
	}
): Promise<LinkSent> {
	const now = epochTime();
	const countKey = `${bucket._id}:${user._id}`;
	const prior = await linkCounts().find(countKey);
	const live = prior && prior.exp > now ? prior : undefined;
	if (rateRefusal(live, now, LINK_BOUNDS)) return 'throttled';
	if (!(await mailDeliveryConfigured())) return 'mail_failed';
	if (!(await admitMailRequest(options.request)).admitted) return 'throttled';

	const token = crypto.randomBytes(32).toString('base64url');
	const digest = digestOf(token);
	await links().upsert(
		digest,
		{
			accountId: user._id,
			bucketId: bucket._id,
			purpose,
			holder,
			...(options.enrolledAt !== undefined
				? { enrolledAt: options.enrolledAt }
				: {}),
			exp: now + LINK_TTL_SECONDS
		},
		LINK_TTL_SECONDS
	);
	const fields = nextRateFields(live, now, LINK_BOUNDS, true);
	const keep = Math.max(
		fields.windowStart + LINK_WINDOW_SECONDS - now,
		LINK_COOLDOWN_SECONDS
	);
	await linkCounts().upsert(
		countKey,
		{
			accountId: user._id,
			...fields,
			latestLink: digest,
			exp: now + keep
		},
		keep
	);
	try {
		await deliver({
			to: user.email,
			...twoStepLinkEmail(
				purpose,
				who(bucket, user),
				options.urlFor(token),
				emailLanguage(user)
			)
		});
	} catch (error) {
		console.error('two-step verification: a link could not be mailed', {
			accountId: user._id,
			error
		});
		return 'mail_failed';
	}
	return 'sent';
}

/*
 * Follows an enrolment link: only in the place it was sent for, only within its ten minutes, only once, and only the
 * newest of the account's links. Answers the link, or nothing — never why, so a link shows nothing to whoever holds it
 * in the wrong browser.
 */
export async function followLink(
	token: string,
	holder: string,
	accountId: string,
	bucketId: string
): Promise<TotpLinkPayload | undefined> {
	if (!token) return undefined;
	const digest = digestOf(token);
	const record = await links().find(digest);
	if (
		!record ||
		record.exp <= epochTime() ||
		record.purpose === 'disown' ||
		record.holder !== holder ||
		record.accountId !== accountId ||
		record.bucketId !== bucketId
	) {
		return undefined;
	}
	const counts = await linkCounts().find(`${bucketId}:${accountId}`);
	if (counts?.latestLink !== digest) return undefined;
	if (!(await links().consume(digest))) return undefined;
	return record;
}

/* The "This wasn't me" link for a factor just set up or replaced: three days, the factor's own. */
async function issueDisownLink(
	bucket: UserBucket,
	accountId: string,
	enrolledAt: number
): Promise<string> {
	const token = crypto.randomBytes(32).toString('base64url');
	await links().upsert(
		digestOf(token),
		{
			accountId,
			bucketId: bucket._id,
			purpose: 'disown',
			enrolledAt,
			exp: epochTime() + DISOWN_TTL_SECONDS
		},
		DISOWN_TTL_SECONDS
	);
	return `${accountPageBase(bucket)}${routeNames.account_security_disown}?token=${encodeURIComponent(token)}`;
}

/* A live "This wasn't me" link, read without spending it, for the confirmation page. */
export async function readDisownLink(
	token: string
): Promise<TotpLinkPayload | undefined> {
	if (!token) return undefined;
	const record = await links().find(digestOf(token));
	return record?.purpose === 'disown' &&
		record.exp > epochTime() &&
		record.enrolledAt !== undefined
		? record
		: undefined;
}

/* Spends a "This wasn't me" link; of two racing confirmations exactly one is told yes. */
export async function spendDisownLink(token: string): Promise<boolean> {
	return token ? links().consume(digestOf(token)) : false;
}

/*
 * Tells the person about a change to their factor, at a confirmed address only: the message names the account's
 * security state, and an address nobody proved may be someone else's. A notice that cannot be sent is logged without
 * the address and never fails what it reports.
 */
export async function notifyTwoStep(
	bucket: UserBucket,
	user: User,
	notice: TwoStepNotice
): Promise<void> {
	if (!user.verified || !user.email) return;
	try {
		await deliver({
			to: user.email,
			...twoStepNoticeEmail(notice, who(bucket, user), emailLanguage(user))
		});
	} catch (error) {
		console.error('two-step verification: a notice could not be sent', {
			accountId: user._id,
			kind: notice.kind,
			error
		});
	}
}

/* The notice for a factor just set up or replaced, with its "This wasn't me" link. */
export async function notifyEnrolled(
	bucket: UserBucket,
	user: User,
	kind: 'on' | 'changed'
): Promise<void> {
	const enrolledAt = enrolmentInstant(user.totp?.enrolledAt);
	if (enrolledAt === undefined) return;
	await notifyTwoStep(bucket, user, {
		kind,
		disownUrl: await issueDisownLink(bucket, user._id, enrolledAt)
	});
}

/*
 * An enrolment completed at sign-in, in a project that requires a factor (or after the link a removal asks for), or
 * from an application that requires one (specs/127, `via: 'self'`: the person's own choice, as on their page). The
 * person is the actor, as on their page; `addressProved` when a mailed link led here.
 */
export async function enrolAtSignIn(
	bucketId: string,
	accountId: string,
	proved: Proved,
	addressProved = false,
	via: 'self' | 'sign-in' = 'sign-in'
): Promise<boolean> {
	const bucket = await getBucketStore().find(bucketId);
	if (!bucket) return false;
	try {
		const user = await enrolOwnAuthenticator(
			bucket,
			accountId,
			{ secret: proved.secret, step: proved.step, via },
			() =>
				recordEndUserAudit(bucketId, accountId, 'enduser.totp.enrol', {
					targetScope: bucketId,
					ownerGroupId: bucket.ownerGroupId
				}),
			{ addressProved }
		);
		await notifyEnrolled(bucket, user, 'on');
		return true;
	} catch (error) {
		if (error instanceof EndUserError && error.status === 404) return false;
		throw error;
	}
}

/*
 * After an enrolment on the page (research R6): the person entered their password in this browser within fifteen
 * minutes, proved the mailbox and the new factor, so the session now counts as signed in with both — an app asking for
 * a multi-factor sign-in need not send them round again. Saved with what is left of its life.
 */
export async function raiseSession(session: Session): Promise<void> {
	session.payload.acr = configuration.acrMap.multi_factor;
	session.payload.amr = [...AMR_FOR_DISTINCTION.multi_factor];
	session.payload.loginTs = epochTime();
	const remaining = (session.payload.exp ?? 0) - epochTime();
	if (remaining > 0) await session.save(remaining);
}

/* The mail that someone signed in with the person's password and could not give the code (specs/126 FR-023). */
export async function warnOfGuessing(
	bucketId: string,
	accountId: string
): Promise<void> {
	const bucket = await getBucketStore().find(bucketId);
	const user = await getUserStore(bucketId).find(accountId);
	if (bucket && user) await notifyTwoStep(bucket, user, { kind: 'guess' });
}
