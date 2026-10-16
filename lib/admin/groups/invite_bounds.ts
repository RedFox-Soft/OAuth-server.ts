import { Type as t, type Static } from '@sinclair/typebox';
import {
	checkedAdapter,
	getGroupInvitationStore
} from '../../adapters/index.js';
import { AdminError } from '../auth/rbac.js';
import epochTime from '../../helpers/epoch_time.js';
import {
	nextRateFields,
	rateRefusal,
	type RateBounds,
	type RateFields
} from '../../helpers/rate_window.js';

/*
 * How much team invitation mail one administrator can cause (specs/103).
 *
 * Invitations go out under the operator's mail identity, carrying a team name the inviter chose, to any address.
 * Unbounded, one tenant could spend the instance's sending reputation for every tenant, or send a phishing-shaped
 * team name to one address over and over. The bounds are the reset and verification flows' arithmetic
 * (lib/helpers/rate_window.ts) under counters of their own:
 *
 * - one address and team: one invitation every 10 minutes, five a day — enough to resend a lost one;
 * - one inviter, across every team: a hundred a day;
 * - one team: fifty open invitations at once.
 *
 * Super administrators are bounded too: these protect the mail identity, not a plan. Two requests at the same
 * moment may each pass a bound once — the race the reset counters and the plan limits accept.
 */

export const TeamInvitationThrottlePayload = t.Object({
	lastSentAt: t.Number(),
	dayCount: t.Number(),
	windowStart: t.Number(),
	exp: t.Number()
});
export type TeamInvitationThrottlePayload = Static<
	typeof TeamInvitationThrottlePayload
>;

const DAY_SECONDS = 86_400;

const PER_ADDRESS: RateBounds = {
	cooldownSeconds: 600,
	cap: 5,
	windowSeconds: DAY_SECONDS
};

const PER_INVITER: RateBounds = {
	cooldownSeconds: 0,
	cap: 100,
	windowSeconds: DAY_SECONDS
};

export const OPEN_INVITATIONS_PER_TEAM = 50;

function counters() {
	return checkedAdapter(
		'TeamInvitationThrottle',
		TeamInvitationThrottlePayload
	);
}

const addressKey = (teamId: string, email: string) => `${teamId}:${email}`;
const inviterKey = (adminId: string) => `inviter:${adminId}`;

function secondsUntilAllowed(
	prior: RateFields,
	now: number,
	bounds: RateBounds,
	refusal: 'cooldown' | 'daily'
): number {
	const until =
		refusal === 'cooldown'
			? prior.lastSentAt + bounds.cooldownSeconds
			: prior.windowStart + bounds.windowSeconds;
	return Math.max(1, until - now);
}

function inWords(seconds: number): string {
	if (seconds < 3600) {
		const minutes = Math.ceil(seconds / 60);
		return `${String(minutes)} minute${minutes === 1 ? '' : 's'}`;
	}
	const hours = Math.ceil(seconds / 3600);
	return `${String(hours)} hour${hours === 1 ? '' : 's'}`;
}

/* Refuses before anything is recorded: checked after authorization and before the audit write. */
export async function assertMayInvite(
	teamId: string,
	email: string,
	inviterId: string
): Promise<void> {
	const now = epochTime();

	const team = await getGroupInvitationStore().listByGroup(teamId);
	const open = team.filter(
		(invitation) =>
			invitation.acceptedAt === null &&
			invitation.expiresAt.getTime() > now * 1000
	);
	if (open.length >= OPEN_INVITATIONS_PER_TEAM) {
		throw new AdminError(
			409,
			`this team has ${String(OPEN_INVITATIONS_PER_TEAM)} open invitations: revoke one or wait for one to be accepted`
		);
	}

	const byAddress = await counters().find(addressKey(teamId, email));
	const addressRefusal = rateRefusal(byAddress, now, PER_ADDRESS);
	if (addressRefusal && byAddress) {
		const retryAfter = secondsUntilAllowed(
			byAddress,
			now,
			PER_ADDRESS,
			addressRefusal
		);
		throw new AdminError(
			429,
			`this address was invited to this team recently: try again in ${inWords(retryAfter)}`,
			{ retryAfter }
		);
	}

	const byInviter = await counters().find(inviterKey(inviterId));
	const inviterRefusal = rateRefusal(byInviter, now, PER_INVITER);
	if (inviterRefusal && byInviter) {
		const retryAfter = secondsUntilAllowed(
			byInviter,
			now,
			PER_INVITER,
			inviterRefusal
		);
		throw new AdminError(
			429,
			`you have sent as many invitations as allowed today: try again in ${inWords(retryAfter)}`,
			{ retryAfter }
		);
	}
}

/* Charged once the invitation exists, whether or not the mail then goes: the mail is what the bounds are about. */
export async function chargeInvitation(
	teamId: string,
	email: string,
	inviterId: string
): Promise<void> {
	const now = epochTime();
	await charge(addressKey(teamId, email), now, PER_ADDRESS);
	await charge(inviterKey(inviterId), now, PER_INVITER);
}

async function charge(
	key: string,
	now: number,
	bounds: RateBounds
): Promise<void> {
	const prior = await counters().find(key);
	await counters().upsert(
		key,
		{ ...nextRateFields(prior, now, bounds, true), exp: now + DAY_SECONDS },
		DAY_SECONDS
	);
}
