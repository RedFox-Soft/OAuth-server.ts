import { adapter } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { Client } from '../models/client.js';
import { Grant } from '../models/grant.js';
import { Session } from '../models/session.js';

/*
 * Where one person is signed in, as an administrator reads it (specs/089): one row per application, read from
 * the person's grants rather than their sessions, because an offline grant outlives the session that made it
 * and is still access the application holds.
 *
 * Names and times only. No network address, browser or device is stored, so none can be shown.
 */
export interface ApplicationSession {
	/* Null for a sign-in that has not reached any application yet. */
	clientId: string | null;
	clientName: string | null;
	/* When the person signed in for this application: the session's sign-in, else the grant's creation. */
	signedInAt: Date | null;
	/*
	 * When this server last issued the application a token for the person — never when the application used
	 * one: a self-contained access token is checked without asking here, and is not stored.
	 */
	lastTokenAt: Date | null;
	/* The application holds access no live session in this bucket carries: offline access. */
	offline: boolean;
}

/* The person's live sessions in this bucket. An account id means nothing outside the bucket that issued it. */
export async function sessionsIn(
	bucketId: string,
	accountId: string
): Promise<Session[]> {
	const stored = await adapter('Session').findByOwner('accountId', accountId);
	const sessions = await Promise.all(
		stored.map((record) => Session.fromStored(record))
	);
	return sessions.filter(
		(s): s is Session => s !== undefined && s.payload.bucketId === bucketId
	);
}

/* The person's grants issued by this bucket; a grant minted before tokens carried a bucket counts as its own. */
export async function grantsIn(
	bucketId: string,
	accountId: string
): Promise<Grant[]> {
	const stored = await adapter('Grant').findByOwner('accountId', accountId);
	const grants = await Promise.all(
		stored.map((record) => Grant.fromStored(record))
	);
	return grants.filter(
		(g): g is Grant =>
			g !== undefined &&
			(g.payload.bucketId === undefined || g.payload.bucketId === bucketId)
	);
}

/* The latest issue time of the person's stored tokens, per grant. */
async function lastIssuedByGrant(
	accountId: string
): Promise<Map<string, number>> {
	const latest = new Map<string, number>();
	for (const area of ['AccessToken', 'RefreshToken']) {
		for (const record of await adapter(area).findByOwner(
			'accountId',
			accountId
		)) {
			const { grantId, iat } = record;
			if (typeof grantId !== 'string' || typeof iat !== 'number') continue;
			latest.set(grantId, Math.max(latest.get(grantId) ?? 0, iat));
		}
	}
	return latest;
}

function dateOf(epochSeconds: number | undefined): Date | null {
	return epochSeconds === undefined ? null : new Date(epochSeconds * 1000);
}

export async function applicationSessions(
	bucket: Pick<UserBucket, '_id'>,
	accountId: string
): Promise<ApplicationSession[]> {
	const [sessions, grants, issued] = await Promise.all([
		sessionsIn(bucket._id, accountId),
		grantsIn(bucket._id, accountId),
		lastIssuedByGrant(accountId)
	]);

	const byClient = new Map<string, Grant[]>();
	for (const grant of grants) {
		const list = byClient.get(grant.payload.clientId) ?? [];
		list.push(grant);
		byClient.set(grant.payload.clientId, list);
	}

	const rows: ApplicationSession[] = [];
	for (const [clientId, clientGrants] of byClient) {
		const grantIds = new Set(clientGrants.map((g) => g.id));
		const holding = sessions.filter((s) => {
			const grantId = s.payload.authorizations?.[clientId]?.grantId;
			return grantId !== undefined && grantIds.has(grantId);
		});
		const loginTs = holding
			.map((s) => s.payload.loginTs)
			.filter((ts): ts is number => ts !== undefined);
		const tokenTimes = clientGrants
			.map((g) => issued.get(g.id))
			.filter((ts): ts is number => ts !== undefined);
		const client = await Client.tryFind(clientId);
		rows.push({
			clientId,
			clientName: client?.clientName ?? null,
			signedInAt: dateOf(
				loginTs.length > 0
					? Math.max(...loginTs)
					: Math.min(...clientGrants.map((g) => g.payload.createdAt))
			),
			lastTokenAt: dateOf(
				tokenTimes.length > 0
					? Math.max(...tokenTimes)
					: Math.max(...clientGrants.map((g) => g.payload.lastModifiedAt))
			),
			offline: holding.length === 0
		});
	}

	/* A sign-in that holds no grant yet: the person is signed in, at no application. */
	for (const session of sessions) {
		const holdsGrant = Object.values(session.payload.authorizations ?? {}).some(
			(a) => a.grantId !== undefined
		);
		if (!holdsGrant) {
			rows.push({
				clientId: null,
				clientName: null,
				signedInAt: dateOf(session.payload.loginTs),
				lastTokenAt: null,
				offline: false
			});
		}
	}

	return rows.sort(
		(a, b) => (b.signedInAt?.getTime() ?? 0) - (a.signedInAt?.getTime() ?? 0)
	);
}
