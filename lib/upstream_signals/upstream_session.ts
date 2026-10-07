import { hash } from 'node:crypto';

import { adapter, checkedAdapter, getUserStore } from '../adapters/index.js';
import { ttl } from '../configs/liveTime.js';
import { areaNamed } from '../consts/storage_inventory.js';
import type { FederationProvider } from '../federation/types.js';
import epochTime from '../helpers/epoch_time.js';
import { Session } from '../models/session.js';
import { destroyProviderSession } from '../shared/destroy_session.js';
import { UpstreamSessionPayload } from './types.js';

/*
 * Which sessions here came from which upstream session (specs/073 research R3–R5).
 *
 * A federated sign-in records its origin on the session — the provider, and a digest of the provider's own
 * session identifier — and, when there is an identifier, an `UpstreamSession` record mapping that upstream
 * session to the account it signed in. Sessions are reachable only by id, uid and owner, so a logout token
 * naming an upstream session alone is resolved through that record to an account, whose sessions are then
 * read and kept only where their origin matches.
 *
 * Accepted limit: the record expires one session lifetime after the sign-in that wrote it, while a session's
 * own lifetime renews with use. A session kept alive past that no longer answers to a token carrying only the
 * upstream session; a token carrying the subject — every token Keycloak, Auth0 and Ping send — still reaches it.
 */

export interface UpstreamOrigin {
	providerId: string;
	sid?: string;
}

/* What a session stores: the provider, and the digest of its session identifier rather than the value. */
export function originOf(upstream: UpstreamOrigin): {
	providerId: string;
	sidDigest?: string;
} {
	return {
		providerId: upstream.providerId,
		...(upstream.sid ? { sidDigest: digest(upstream.sid) } : {})
	};
}

function digest(value: string): string {
	return hash('sha256', value, 'hex');
}

/* Bucket and provider ids hold no `:`, and `sid` comes last, so no two triples share a key. */
function recordIdFor(bucketId: string, providerId: string, sid: string) {
	return digest(`${bucketId}:${providerId}:${sid}`);
}

function records() {
	return checkedAdapter('UpstreamSession', UpstreamSessionPayload);
}

export async function rememberUpstreamSession(
	bucketId: string,
	upstream: UpstreamOrigin,
	accountId: string
): Promise<void> {
	if (!upstream.sid) return;
	await records().upsert(
		recordIdFor(bucketId, upstream.providerId, upstream.sid),
		{ accountId, exp: epochTime() + ttl.Session },
		ttl.Session
	);
}

async function sessionsOfAccount(
	bucketId: string,
	accountId: string
): Promise<Session[]> {
	const area = areaNamed('Session');
	const field = area.owners.account;
	if (field === null) {
		/* Unreachable while the inventory declares Session account-owned; a loud stop beats a silent skip. */
		throw new Error('the Session area declares no account owner to read by');
	}
	const stored = await adapter(area.name).findByOwner(field, accountId);
	const sessions = await Promise.all(
		stored.map((record) => Session.fromStored(record))
	);
	return sessions.filter(
		(session): session is Session =>
			session !== undefined && session.payload.bucketId === bucketId
	);
}

/*
 * The sessions whose latest sign-in came through `sid` at `provider`. With `accountId`, only that account's —
 * a logout token naming both a subject and a session must not end somebody else's session.
 */
export async function sessionsFromUpstreamSession(
	bucketId: string,
	provider: FederationProvider,
	sid: string,
	accountId?: string
): Promise<Session[]> {
	const record = await records().find(recordIdFor(bucketId, provider.id, sid));
	if (!record || record.exp <= epochTime()) return [];
	if (accountId !== undefined && record.accountId !== accountId) return [];
	const sidDigest = digest(sid);
	return (await sessionsOfAccount(bucketId, record.accountId)).filter(
		(session) =>
			session.payload.upstream?.providerId === provider.id &&
			session.payload.upstream.sidDigest === sidDigest
	);
}

/* Every session of the account linked to `sub` at `provider` whose latest sign-in came through that provider. */
export async function sessionsOfSubject(
	bucketId: string,
	provider: FederationProvider,
	sub: string
): Promise<Session[]> {
	const user = await getUserStore(bucketId).findByFederatedIdentity(
		provider.id,
		sub
	);
	if (!user) return [];
	return (await sessionsOfAccount(bucketId, user._id)).filter(
		(session) => session.payload.upstream?.providerId === provider.id
	);
}

/* The account linked to `sub` at `provider` in this bucket, if any. */
export async function accountLinkedTo(
	bucketId: string,
	provider: FederationProvider,
	sub: string
): Promise<string | undefined> {
	const user = await getUserStore(bucketId).findByFederatedIdentity(
		provider.id,
		sub
	);
	return user?._id;
}

/*
 * Each session ends exactly as a sign-out here ends it: relying parties told, the grants that do not outlive
 * a sign-out revoked, offline access kept, the record destroyed (Back-Channel Logout 1.0 §2.7).
 */
export async function endSessions(sessions: Session[]): Promise<number> {
	for (const session of sessions) {
		await destroyProviderSession(session);
	}
	return sessions.length;
}
