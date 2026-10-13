import { adapter } from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { Client } from '../models/client.js';
import { Grant } from '../models/grant.js';
import { Session } from '../models/session.js';
import epochTime from '../helpers/epoch_time.js';
import { isAccountPageClient } from '../account_page/client.js';

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

export interface IssuedTokens {
	/* The latest issue time, in epoch seconds, of the person's stored access and refresh tokens, per grant. */
	latest: Map<string, number>;
	/* The grants holding a refresh token that is neither used up nor expired: access that outlives a sign-out. */
	liveRefresh: Set<string>;
}

export async function issuedTokens(accountId: string): Promise<IssuedTokens> {
	const latest = new Map<string, number>();
	const liveRefresh = new Set<string>();
	const now = epochTime();
	for (const area of ['AccessToken', 'RefreshToken']) {
		for (const record of await adapter(area).findByOwner(
			'accountId',
			accountId
		)) {
			const { grantId, iat, exp, consumed } = record;
			if (typeof grantId !== 'string' || typeof iat !== 'number') continue;
			latest.set(grantId, Math.max(latest.get(grantId) ?? 0, iat));
			if (
				area === 'RefreshToken' &&
				!consumed &&
				(typeof exp !== 'number' || exp > now)
			) {
				liveRefresh.add(grantId);
			}
		}
	}
	return { latest, liveRefresh };
}

function dateOfSeconds(epochSeconds: number | undefined): Date | null {
	return epochSeconds === undefined ? null : new Date(epochSeconds * 1000);
}

/*
 * The person's grants per application, without the bucket's connected-apps page client: signing in to one's
 * own account page leaves a grant behind (every authorization does), and it is not an application the person
 * connected anything to (specs/095 R3).
 */
function grantsByClient(grants: readonly Grant[]): Map<string, Grant[]> {
	const byClient = new Map<string, Grant[]>();
	for (const grant of grants) {
		if (isAccountPageClient(grant.payload.clientId)) continue;
		const list = byClient.get(grant.payload.clientId) ?? [];
		list.push(grant);
		byClient.set(grant.payload.clientId, list);
	}
	return byClient;
}

export async function applicationSessions(
	bucket: Pick<UserBucket, '_id'>,
	accountId: string
): Promise<ApplicationSession[]> {
	const [sessions, grants, issued] = await Promise.all([
		sessionsIn(bucket._id, accountId),
		grantsIn(bucket._id, accountId),
		issuedTokens(accountId)
	]);

	const rows: ApplicationSession[] = [];
	for (const [clientId, clientGrants] of grantsByClient(grants)) {
		const grantIds = new Set(clientGrants.map((g) => g.id));
		const holding = sessions.filter((s) => {
			const grantId = s.payload.authorizations?.[clientId]?.grantId;
			return grantId !== undefined && grantIds.has(grantId);
		});
		const loginTs = holding
			.map((s) => s.payload.loginTs)
			.filter((ts): ts is number => ts !== undefined);
		const tokenTimes = clientGrants
			.map((g) => issued.latest.get(g.id))
			.filter((ts): ts is number => ts !== undefined);
		const client = await Client.tryFind(clientId);
		/*
		 * A sign-in and a token's issue time are epoch seconds; a grant's own times are milliseconds
		 * (`Date.now()` in lib/models/grant.ts). Read as seconds, a grant's date landed some fifty thousand
		 * years ahead.
		 */
		rows.push({
			clientId,
			clientName: client?.clientName ?? null,
			signedInAt:
				loginTs.length > 0
					? dateOfSeconds(Math.max(...loginTs))
					: new Date(Math.min(...clientGrants.map((g) => g.payload.createdAt))),
			lastTokenAt:
				tokenTimes.length > 0
					? dateOfSeconds(Math.max(...tokenTimes))
					: new Date(
							Math.max(...clientGrants.map((g) => g.payload.lastModifiedAt))
						),
			offline: holding.length === 0
		});
	}

	/* A sign-in that holds no grant yet: the person is signed in, at no application. */
	for (const session of sessions) {
		const holdsGrant = Object.entries(
			session.payload.authorizations ?? {}
		).some(
			([clientId, a]) =>
				a.grantId !== undefined && !isAccountPageClient(clientId)
		);
		if (!holdsGrant) {
			rows.push({
				clientId: null,
				clientName: null,
				signedInAt: dateOfSeconds(session.payload.loginTs),
				lastTokenAt: null,
				offline: false
			});
		}
	}

	return rows.sort(
		(a, b) => (b.signedInAt?.getTime() ?? 0) - (a.signedInAt?.getTime() ?? 0)
	);
}

/* One application holding access for the person, as their connected-applications page reads it (specs/095). */
export interface ConnectedApplication {
	clientId: string;
	grants: Grant[];
	/* Epoch seconds; absent when no stored token was issued under its grants. */
	lastTokenAt?: number;
	/* A refresh token under its grants is live: it keeps access after the person signs out. */
	liveRefresh: boolean;
}

/*
 * Read from grants rather than sessions for the reason `applicationSessions` is: access an application holds
 * offline outlives the sign-in that gave it, and is exactly what the person needs to see.
 */
export async function connectedApplications(
	bucket: Pick<UserBucket, '_id'>,
	accountId: string
): Promise<ConnectedApplication[]> {
	const [grants, issued] = await Promise.all([
		grantsIn(bucket._id, accountId),
		issuedTokens(accountId)
	]);
	const applications: ConnectedApplication[] = [];
	for (const [clientId, clientGrants] of grantsByClient(grants)) {
		const times = clientGrants
			.map((g) => issued.latest.get(g.id))
			.filter((ts): ts is number => ts !== undefined);
		applications.push({
			clientId,
			grants: clientGrants,
			...(times.length > 0 ? { lastTokenAt: Math.max(...times) } : undefined),
			liveRefresh: clientGrants.some((g) => issued.liveRefresh.has(g.id))
		});
	}
	return applications;
}
