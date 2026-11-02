import { getBucketStore, getConnectedAccountStore } from '../adapters/index.js';
import epochTime from '../helpers/epoch_time.js';
import { connectedAccountKey } from '../models/grant.js';
import { grantsIn } from '../end_users/sessions.js';
import { serviceOf } from './accounts.js';
import { freshAccount } from './refresh.js';
import type { ConnectedAccount } from './types.js';

/*
 * Keeping refresh tokens alive while they are used (specs/118 R11). Google discards one unused for six months,
 * Microsoft's lapse after ninety days without use, GitHub's after six months: refreshing every thirty days stays
 * inside all three without a table of provider limits that would be wrong the day one changes. Only accounts an
 * agent may use and did use within a year: a token nobody needs is left to lapse, as the clarification decided.
 */

const DAY = 86_400;
export const KEEP_ALIVE_INTERVAL_SECONDS = 30 * DAY;
const EXPIRING_WITHIN_SECONDS = 7 * DAY;
export const KEEP_ALIVE_UNUSED_SECONDS = 365 * DAY;
const PER_PASS = 200;

function due(record: ConnectedAccount, now: number): boolean {
	return (
		(record.refreshedAt ?? 0) < now - KEEP_ALIVE_INTERVAL_SECONDS ||
		(record.refreshTokenExpiresAt !== undefined &&
			record.refreshTokenExpiresAt < now + EXPIRING_WITHIN_SECONDS)
	);
}

/* Refreshes what is due; answers how many it refreshed. Several processes may run it at once (FR-016). */
export async function keepAlivePass(now = epochTime()): Promise<number> {
	const candidates = await getConnectedAccountStore().listKeepAliveDue({
		staleBefore: now - KEEP_ALIVE_INTERVAL_SECONDS,
		expiringBefore: now + EXPIRING_WITHIN_SECONDS,
		usedSince: now - KEEP_ALIVE_UNUSED_SECONDS,
		limit: PER_PASS
	});
	let refreshed = 0;
	for (const record of candidates) {
		try {
			const grants = await grantsIn(record.bucketId, record.accountId);
			const key = connectedAccountKey(record._id);
			if (!grants.some((grant) => grant.connectedConsent(key) === 'allowed')) {
				continue;
			}
			const bucket = await getBucketStore().find(record.bucketId);
			const service = bucket ? serviceOf(bucket, record.serviceId) : undefined;
			if (!bucket || !service || bucket.deletion !== undefined) continue;
			/* Read again under the lease: another process may have refreshed it since the list was read. */
			const outcome = await freshAccount(
				bucket,
				service,
				record,
				'keep_alive',
				(current) => due(current, now)
			);
			if (
				outcome.kind === 'fresh' &&
				outcome.record.refreshedAt !== record.refreshedAt
			) {
				refreshed += 1;
			}
		} catch (error) {
			console.error('connected services: keeping an account alive failed', {
				connectedAccountId: record._id,
				error
			});
		}
	}
	return refreshed;
}

export function startKeepAlive(
	intervalMs: number = 60 * 60 * 1000
): () => void {
	const timer = setInterval(() => {
		void keepAlivePass().catch((error: unknown) => {
			console.error(
				'connected services: the keep-alive pass failed; the next pass will retry',
				error
			);
		});
	}, intervalMs);
	timer.unref();
	return () => clearInterval(timer);
}
