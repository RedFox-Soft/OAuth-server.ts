import { randomUUID } from 'node:crypto';

import { getConnectedAccountStore } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { eventBus } from '../event_bus.js';
import epochTime from '../helpers/epoch_time.js';
import { resolveService } from './catalogue.js';
import { refreshUpstream } from './exchange.js';
import { noticeBroken } from './mail.js';
import type {
	ConnectedAccount,
	ConnectedAccountBreak,
	ConnectedService
} from './types.js';

/*
 * The only way a stored upstream token is renewed (specs/118 R9): one refresh per account at a time, in this process
 * and across every process sharing the datastore. GitHub and Slack issue a new refresh token on every refresh and
 * refuse the old one, so a second concurrent refresh would lose the account for good.
 */

/* A token with less than this left is refreshed before it is handed out (spec assumption "safety margin"). */
export const SAFETY_MARGIN_SECONDS = 60;
/* Twice the outbound bound of one refresh (10 s), so a dead holder is taken over (FR-011). */
const LEASE_SECONDS = 20;
const WAIT_MS = 12_000;
const POLL_MS = 200;

export type Trigger = 'exchange' | 'keep_alive' | 'revocation';

export type Freshness =
	| { kind: 'fresh'; record: ConnectedAccount }
	| { kind: 'broken' }
	| { kind: 'unavailable' }
	| { kind: 'gone' };

export function expiresSoon(record: ConnectedAccount, now = epochTime()) {
	return (
		record.accessTokenExpiresAt !== undefined &&
		record.accessTokenExpiresAt - SAFETY_MARGIN_SECONDS <= now
	);
}

function eventOf(record: ConnectedAccount) {
	return {
		bucketId: record.bucketId,
		serviceId: record.serviceId,
		connectedAccountId: record._id,
		accountId: record.accountId
	};
}

const flights = new Map<string, Promise<Freshness>>();

/*
 * The account with a usable access token: as stored while `due` says it is not due, else refreshed. `due` is the
 * caller's test, read again once the lease is held, so a refresh another process just finished is not repeated.
 */
export function freshAccount(
	bucket: UserBucket,
	service: ConnectedService,
	record: ConnectedAccount,
	trigger: Trigger,
	due: (record: ConnectedAccount) => boolean = (current) => expiresSoon(current)
): Promise<Freshness> {
	if (record.broken) return Promise.resolve({ kind: 'broken' });
	if (!due(record)) return Promise.resolve({ kind: 'fresh', record });
	const running = flights.get(record._id);
	if (running) return running;
	const flight = refreshOnce(bucket, service, record, trigger, due).finally(
		() => flights.delete(record._id)
	);
	flights.set(record._id, flight);
	return flight;
}

async function refreshOnce(
	bucket: UserBucket,
	service: ConnectedService,
	record: ConnectedAccount,
	trigger: Trigger,
	due: (record: ConnectedAccount) => boolean
): Promise<Freshness> {
	const store = getConnectedAccountStore();
	const holder = randomUUID();
	const deadline = Date.now() + WAIT_MS;
	for (;;) {
		const now = epochTime();
		const claimed = await store.claimRefresh(
			bucket._id,
			record._id,
			holder,
			now,
			now + LEASE_SECONDS
		);
		if (claimed)
			return refreshClaimed(bucket, service, claimed, trigger, due, holder);

		const current = await store.find(bucket._id, record._id);
		if (!current) return { kind: 'gone' };
		if (current.broken) return { kind: 'broken' };
		if (!due(current)) return { kind: 'fresh', record: current };
		if (Date.now() >= deadline) return { kind: 'unavailable' };
		await Bun.sleep(POLL_MS);
	}
}

async function refreshClaimed(
	bucket: UserBucket,
	service: ConnectedService,
	claimed: ConnectedAccount,
	trigger: Trigger,
	due: (record: ConnectedAccount) => boolean,
	holder: string
): Promise<Freshness> {
	const store = getConnectedAccountStore();
	let written = false;
	try {
		if (claimed.broken) return { kind: 'broken' };
		if (!due(claimed)) return { kind: 'fresh', record: claimed };
		if (!claimed.refreshToken || !service.clientSecret) {
			return { kind: 'unavailable' };
		}

		let resolved;
		try {
			resolved = await resolveService(service);
		} catch {
			return { kind: 'unavailable' };
		}
		const outcome = await refreshUpstream(
			resolved,
			{ clientId: service.clientId, clientSecret: service.clientSecret },
			claimed.refreshToken,
			claimed.upstreamId
		);
		if (outcome.kind === 'unavailable') return { kind: 'unavailable' };
		if (outcome.kind !== 'refreshed') {
			written = true;
			await breakAccount(
				bucket,
				claimed,
				outcome.kind === 'rejected' ? 'refresh_rejected' : 'identity_changed'
			);
			return { kind: 'broken' };
		}

		const { tokens } = outcome;
		let saved = false;
		try {
			saved = await store.finishRefresh(bucket._id, claimed._id, holder, {
				accessToken: tokens.accessToken,
				...(tokens.refreshToken ? { refreshToken: tokens.refreshToken } : {}),
				tokenType: tokens.tokenType,
				...(tokens.accessTokenExpiresAt
					? { accessTokenExpiresAt: tokens.accessTokenExpiresAt }
					: {}),
				...(tokens.refreshTokenExpiresAt
					? { refreshTokenExpiresAt: tokens.refreshTokenExpiresAt }
					: {}),
				scopes: tokens.grantedScopes ?? claimed.scopes,
				refreshedAt: epochTime()
			});
		} catch {
			saved = false;
		}
		written = true;
		if (!saved) {
			/*
			 * The provider has answered, so a rotating refresh token is already spent: keeping the old one would only
			 * fail later and less clearly (FR-013).
			 */
			await breakAccount(bucket, claimed, 'refresh_unsaved');
			return { kind: 'broken' };
		}
		eventBus.emit('connected_account.refreshed', {
			...eventOf(claimed),
			trigger
		});
		const after = await store.find(bucket._id, claimed._id);
		return after ? { kind: 'fresh', record: after } : { kind: 'gone' };
	} finally {
		if (!written) {
			await store
				.releaseRefresh(bucket._id, claimed._id, holder)
				.catch(() => undefined);
		}
	}
}

async function breakAccount(
	bucket: UserBucket,
	record: ConnectedAccount,
	reason: ConnectedAccountBreak
): Promise<void> {
	let first = false;
	try {
		({ first } = await getConnectedAccountStore().markBroken(
			bucket._id,
			record._id,
			reason,
			epochTime()
		));
	} catch (error) {
		console.error('connected services: an account could not be marked broken', {
			connectedAccountId: record._id,
			error
		});
	}
	eventBus.emit('connected_account.broken', { ...eventOf(record), reason });
	if (first) noticeBroken(bucket, record);
}
