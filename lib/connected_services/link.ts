import crypto from 'crypto';

import { checkedAdapter } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { connectLinkUrl } from '../account_page/client.js';
import { eventBus } from '../event_bus.js';
import epochTime from '../helpers/epoch_time.js';
import {
	ConnectLinkPayload,
	type ConnectLinkAct,
	type ConnectLinkPayload as ConnectLink
} from './types.js';

/*
 * An agent's connect link (specs/119 R3, R4): the address an exchange refusal hands the agent, so the person can do
 * the one thing only they can. One slot per person, agent and service: a retry gets the same link, a different act
 * replaces it, and a person's open links are bounded by their agents and the project's services with no counter.
 */

/* Clarified: long enough for a sign-in with a second factor, or a password reset by mail. */
export const LINK_TTL_SECONDS = 1800;

function records() {
	return checkedAdapter('ConnectLink', ConnectLinkPayload);
}

export function slotOf(link: {
	bucketId: string;
	accountId: string;
	clientId: string;
	serviceId: string;
}): string {
	return crypto
		.createHash('sha256')
		.update(
			[link.bucketId, link.accountId, link.clientId, link.serviceId].join('\0')
		)
		.digest('hex');
}

function eventOf(link: ConnectLink) {
	return {
		bucketId: link.bucketId,
		accountId: link.accountId,
		clientId: link.clientId,
		exchangedBy: link.exchangedBy,
		serviceId: link.serviceId,
		act: link.act,
		connectId: link.ref
	};
}

export interface IssuedLink {
	uri: string;
	ref: string;
	expiresIn: number;
}

export async function issueLink(input: {
	bucket: UserBucket;
	accountId: string;
	clientId: string;
	exchangedBy: string;
	serviceId: string;
	act: ConnectLinkAct;
	connectedAccountId?: string;
}): Promise<IssuedLink> {
	const now = epochTime();
	const slot = slotOf({ ...input, bucketId: input.bucket._id });
	const current = await records().find(slot);
	if (
		current &&
		current.state === 'open' &&
		current.exp > now &&
		current.act === input.act &&
		current.connectedAccountId === input.connectedAccountId &&
		current.exchangedBy === input.exchangedBy
	) {
		return {
			uri: connectLinkUrl(input.bucket, current.uid),
			ref: current.ref,
			expiresIn: current.exp - now
		};
	}
	/*
	 * Two first refusals racing both write; the later wins and the earlier link reads as no longer valid. No lock for
	 * a race whose only effect is one stale link (R4).
	 */
	const link: ConnectLink = {
		uid: crypto.randomBytes(32).toString('base64url'),
		ref: crypto.randomBytes(16).toString('base64url'),
		bucketId: input.bucket._id,
		accountId: input.accountId,
		clientId: input.clientId,
		exchangedBy: input.exchangedBy,
		serviceId: input.serviceId,
		act: input.act,
		...(input.connectedAccountId
			? { connectedAccountId: input.connectedAccountId }
			: {}),
		state: 'open',
		iat: now,
		exp: now + LINK_TTL_SECONDS
	};
	await records().upsert(slot, link, LINK_TTL_SECONDS);
	eventBus.emit('connect_link.issued', eventOf(link));
	return {
		uri: connectLinkUrl(input.bucket, link.uid),
		ref: link.ref,
		expiresIn: LINK_TTL_SECONDS
	};
}

/* A link by its value, while it lives: expiry compared here as well as reaped, because a reaper runs late. */
export async function findLink(
	value: string
): Promise<ConnectLink | undefined> {
	if (!value) return undefined;
	const link = await records().findByUid(value);
	if (!link || link.exp <= epochTime()) return undefined;
	return link;
}

/*
 * Closes a link, kept until it would have expired so its person can be told it was done. Only the link that is
 * still in its slot: a replacement written meanwhile is not closed on the older one's behalf.
 */
export async function closeLink(
	value: string,
	slot: string,
	state: 'completed' | 'declined',
	connectedAccountId?: string
): Promise<void> {
	const current = await records().find(slot);
	if (!current || current.uid !== value || current.state !== 'open') return;
	const remaining = current.exp - epochTime();
	if (remaining <= 0) return;
	await records().upsert(slot, { ...current, state }, remaining);
	if (state === 'declined') {
		eventBus.emit('connect_link.declined', eventOf(current));
	} else {
		eventBus.emit('connect_link.completed', {
			...eventOf(current),
			connectedAccountId: connectedAccountId ?? ''
		});
	}
}

export function refusedEvent(
	link: ConnectLink,
	cause: 'other_person' | 'changed'
): void {
	eventBus.emit('connect_link.refused', {
		bucketId: link.bucketId,
		serviceId: link.serviceId,
		connectId: link.ref,
		cause
	});
}
