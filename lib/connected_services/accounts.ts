import crypto from 'crypto';

import { getConnectedAccountStore } from '../adapters/index.js';
import epochTime from '../helpers/epoch_time.js';
import type { UserBucket } from '../adapters/types.js';
import { eventBus, type RevocationOutcome } from '../event_bus.js';
import { activeKeyring } from '../sealing/keyring.js';
import { unreadableFieldsOf } from '../sealing/decorators.js';
import { connectedServiceEntry } from '../consts/connected_service_catalogue.js';
import {
	connectCallbackUri,
	resolveService,
	type ResolvedService
} from './catalogue.js';
import {
	exchangeConnectCode,
	refreshUpstream,
	type IssuedTokens
} from './exchange.js';
import { expiresSoon } from './refresh.js';
import { authorizationRedirect, requestedScopes } from './flow.js';
import { identify } from './identity.js';
import { noticeRemoved } from './mail.js';
import { adoptFirstAccount } from './consent.js';
import { revokeUpstream } from './revoke.js';
import { openConnect } from './state.js';
import type {
	ConnectedAccount,
	ConnectedAccountBreak,
	ConnectedService,
	ConnectStatePayload
} from './types.js';

/*
 * Every change to a connected account (specs/117), as lib/end_users/service.ts is for an end user: the account
 * page, the admin routes and the deletion cascades all come through here, so "deleted locally first, then the
 * provider asked" is one property of one module.
 */

/* A person's accounts at one service: enough for several work and personal accounts, a bound against abuse. */
export const ACCOUNTS_PER_SERVICE = 10;

/* How many provider revocations one cascade keeps in flight. */
const REVOCATIONS_IN_FLIGHT = 4;

export type ConnectNotice =
	'declined' | 'failed' | 'limit' | 'unavailable' | 'expired' | 'refused';

export class ConnectRefused extends Error {
	constructor(readonly notice: ConnectNotice) {
		super(`connect refused: ${notice}`);
	}
}

export function serviceOf(
	bucket: UserBucket,
	serviceId: string
): ConnectedService | undefined {
	return (bucket.connectedServices ?? []).find(
		(service) => service.id === serviceId
	);
}

/*
 * Derived from the four things that make an account one account, so a reconnect lands on the same record by
 * its key on every backend. Base64url of a SHA-256: opaque, fixed length, safe in a path.
 */
export function connectedAccountId(
	bucketId: string,
	serviceId: string,
	accountId: string,
	upstreamId: string
): string {
	return crypto
		.createHash('sha256')
		.update([bucketId, serviceId, accountId, upstreamId].join('\u0000'))
		.digest('base64url');
}

// ---------------------------------------------------------------- connecting

export async function startConnect(input: {
	bucket: UserBucket;
	serviceId: string;
	accountId: string;
	sessionId: string;
}): Promise<string> {
	const service = serviceOf(input.bucket, input.serviceId);
	if (!service) throw new ConnectRefused('refused');
	if (!activeKeyring() || !service.clientSecret) {
		throw new ConnectRefused('unavailable');
	}
	let resolved: ResolvedService;
	try {
		resolved = await resolveService(service);
	} catch {
		throw new ConnectRefused('unavailable');
	}
	const scopes = requestedScopes(resolved, service.scopes);
	const secrets = await openConnect({
		bucketId: input.bucket._id,
		serviceId: service.id,
		accountId: input.accountId,
		sessionId: input.sessionId,
		withPkce: resolved.pkce,
		withNonce: resolved.oidc !== undefined,
		requestedScopes: scopes
	});
	return authorizationRedirect(
		resolved,
		service.clientId,
		connectCallbackUri(input.bucket),
		service.scopes,
		secrets
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

/*
 * Finishes a flow the callback has already proven belongs to this session, person and project. Redeems the
 * code, identifies the account, and stores it; whatever the provider issued is revoked when it is not kept.
 */
export async function finishConnect(input: {
	bucket: UserBucket;
	pending: ConnectStatePayload;
	code: string;
	iss: string | undefined;
}): Promise<{ done: 'connected' | 'updated'; record: ConnectedAccount }> {
	const { bucket, pending } = input;
	const service = serviceOf(bucket, pending.serviceId);
	if (!service || !activeKeyring() || !service.clientSecret) {
		throw new ConnectRefused('unavailable');
	}
	const client = {
		clientId: service.clientId,
		clientSecret: service.clientSecret
	};
	let resolved: ResolvedService;
	try {
		resolved = await resolveService(service);
	} catch {
		throw new ConnectRefused('unavailable');
	}
	assertResponseIssuer(resolved, input.iss);

	let tokens: IssuedTokens;
	try {
		tokens = await exchangeConnectCode(
			resolved,
			client,
			input.code,
			connectCallbackUri(bucket),
			pending.verifier
		);
	} catch {
		throw new ConnectRefused('failed');
	}

	let upstream;
	try {
		upstream = await identify(resolved, client, tokens, pending.nonce);
	} catch {
		await revokeUpstream(resolved, client, tokens);
		throw new ConnectRefused('failed');
	}

	const store = getConnectedAccountStore();
	const id = connectedAccountId(
		bucket._id,
		service.id,
		pending.accountId,
		upstream.upstreamId
	);
	const existing = await store.find(bucket._id, id);
	const atService = existing
		? undefined
		: await store.countByAccountAndService(
				bucket._id,
				pending.accountId,
				service.id
			);
	if (atService !== undefined && atService >= ACCOUNTS_PER_SERVICE) {
		await revokeUpstream(resolved, client, tokens);
		throw new ConnectRefused('limit');
	}

	const now = new Date().toISOString();
	const granted = tokens.grantedScopes;
	const record: ConnectedAccount = {
		_id: id,
		bucketId: bucket._id,
		serviceId: service.id,
		accountId: pending.accountId,
		upstreamId: upstream.upstreamId,
		label: upstream.label,
		accessToken: tokens.accessToken,
		...(tokens.refreshToken ? { refreshToken: tokens.refreshToken } : {}),
		tokenType: tokens.tokenType,
		...(tokens.accessTokenExpiresAt
			? { accessTokenExpiresAt: tokens.accessTokenExpiresAt }
			: {}),
		...(tokens.refreshTokenExpiresAt
			? { refreshTokenExpiresAt: tokens.refreshTokenExpiresAt }
			: {}),
		scopes: granted ?? pending.requestedScopes,
		scopesInferred: granted === undefined,
		connectedAt: existing?.connectedAt ?? now,
		updatedAt: now,
		refreshedAt: epochTime(),
		/* A reconnect keeps when each agent last used the account; it clears `broken`, which re-arms its mail. */
		...(existing?.usedBy ? { usedBy: existing.usedBy } : {})
	};
	const { created } = await store.put(record);
	/* An answer given about the service before any account existed is this first account's (specs/118 FR-020). */
	if (created && atService === 0) await adoptFirstAccount(bucket, record);
	eventBus.emit(
		created ? 'connected_account.connected' : 'connected_account.updated',
		eventOf(record)
	);
	return { done: created ? 'connected' : 'updated', record };
}

/*
 * RFC 9207: an answer naming another issuer is refused before its code is spent, and a provider that says it
 * always names itself must. A templated issuer (Microsoft's `{tenantid}`) is not a string to compare.
 */
function assertResponseIssuer(
	service: ResolvedService,
	iss: string | undefined
): void {
	const metadata = service.oidc?.metadata;
	if (!metadata || metadata.issuer.includes('{')) return;
	if (iss === undefined) {
		if (metadata.issParameterSupported === true) {
			throw new ConnectRefused('refused');
		}
		return;
	}
	if (iss !== metadata.issuer) throw new ConnectRefused('refused');
}

// ---------------------------------------------------------------- reading

export type ConnectedAccountStatus = 'connected' | 'needs_reconnection';

export interface ConnectedAccountView {
	id: string;
	serviceId: string;
	serviceName: string;
	upstreamId: string;
	label: string;
	scopes: string[];
	scopesInferred: boolean;
	missingScopes: string[];
	connectedAt: string;
	updatedAt: string;
	accessTokenExpiresAt?: number;
	status: ConnectedAccountStatus;
	/* Why the provider no longer honours it, and since when (specs/118 R12). */
	broken?: { reason: ConnectedAccountBreak; at: string };
	lastRefreshedAt?: string;
}

export function statusOf(record: ConnectedAccount): ConnectedAccountStatus {
	return record.broken !== undefined ||
		unreadableFieldsOf(record).length > 0 ||
		!record.accessToken
		? 'needs_reconnection'
		: 'connected';
}

export function viewOf(
	bucket: UserBucket,
	record: ConnectedAccount
): ConnectedAccountView {
	const service = serviceOf(bucket, record.serviceId);
	const granted = new Set(record.scopes);
	return {
		id: record._id,
		serviceId: record.serviceId,
		serviceName: service?.displayName ?? record.serviceId,
		upstreamId: record.upstreamId,
		label: record.label,
		scopes: record.scopes,
		scopesInferred: record.scopesInferred,
		missingScopes: record.scopesInferred
			? []
			: (service?.scopes ?? []).filter((scope) => !granted.has(scope)),
		connectedAt: record.connectedAt,
		updatedAt: record.updatedAt,
		...(record.accessTokenExpiresAt
			? { accessTokenExpiresAt: record.accessTokenExpiresAt }
			: {}),
		status: statusOf(record),
		...(record.broken
			? {
					broken: {
						reason: record.broken.reason,
						at: new Date(record.broken.at * 1000).toISOString()
					}
				}
			: {}),
		...(record.refreshedAt
			? { lastRefreshedAt: new Date(record.refreshedAt * 1000).toISOString() }
			: {})
	};
}

export async function listForPerson(
	bucket: UserBucket,
	accountId: string
): Promise<ConnectedAccountView[]> {
	const records = await getConnectedAccountStore().listByAccount(
		bucket._id,
		accountId
	);
	return records
		.map((record) => viewOf(bucket, record))
		.sort((a, b) => a.connectedAt.localeCompare(b.connectedAt));
}

// ---------------------------------------------------------------- removing

/*
 * Whether a service can be asked to revoke at all, known without reaching it: a catalogue entry that has no
 * revocation (Microsoft), or a plain OAuth 2.0 service that declared no endpoint. An OpenID Connect service is
 * known only from its discovery document.
 */
function revocable(service: ConnectedService): boolean {
	if (service.kind === 'catalogue') {
		const entry = service.catalogueId
			? connectedServiceEntry(service.catalogueId)
			: undefined;
		return entry !== undefined && entry.revocation.kind !== 'none';
	}
	if (service.kind === 'oauth2')
		return service.revocationEndpoint !== undefined;
	return true;
}

/* What a person's own disconnect gives a refresh before revoking, so both fit its five seconds (specs/118 R14). */
const REFRESH_BEFORE_REVOKE_MS = 1_000;

/*
 * GitHub's grant deletion and Slack's `auth.revoke` authenticate with the access token, so an expired one cannot
 * revoke anything (specs/117's known limit). Refreshed first, without a lease: the record is already deleted, so
 * nothing else can be refreshing it. Whatever goes wrong, the stored tokens are revoked as they are.
 */
async function revocableTokens(
	resolved: ResolvedService,
	service: ConnectedService,
	record: ConnectedAccount,
	budgetMs: number | undefined
): Promise<{ refreshToken?: string; accessToken?: string }> {
	const stored = {
		...(record.refreshToken ? { refreshToken: record.refreshToken } : {}),
		...(record.accessToken ? { accessToken: record.accessToken } : {})
	};
	const kind = resolved.revocation.kind;
	if (
		(kind !== 'github_grant' && kind !== 'slack') ||
		!record.refreshToken ||
		!service.clientSecret ||
		!expiresSoon(record)
	) {
		return stored;
	}
	const refresh = refreshUpstream(
		resolved,
		{ clientId: service.clientId, clientSecret: service.clientSecret },
		record.refreshToken,
		record.upstreamId
	);
	const outcome =
		budgetMs === undefined
			? await refresh
			: await Promise.race([
					refresh,
					Bun.sleep(budgetMs).then(() => ({ kind: 'unavailable' }) as const)
				]);
	if (outcome.kind !== 'refreshed') return stored;
	eventBus.emit('connected_account.refreshed', {
		...eventOf(record),
		trigger: 'revocation'
	});
	return {
		refreshToken: outcome.tokens.refreshToken ?? record.refreshToken,
		accessToken: outcome.tokens.accessToken
	};
}

async function revokeOne(
	bucket: UserBucket,
	record: ConnectedAccount,
	refreshBudgetMs?: number
): Promise<RevocationOutcome> {
	const service = serviceOf(bucket, record.serviceId);
	let outcome: RevocationOutcome;
	if (!service || !revocable(service)) {
		outcome = 'not_supported';
	} else if (unreadableFieldsOf(record).length > 0 && !record.accessToken) {
		outcome = 'unreadable';
	} else {
		try {
			const resolved = await resolveService(service);
			outcome = await revokeUpstream(
				resolved,
				{
					clientId: service.clientId,
					...(service.clientSecret
						? { clientSecret: service.clientSecret }
						: {})
				},
				await revocableTokens(resolved, service, record, refreshBudgetMs)
			);
		} catch {
			outcome = 'failed';
		}
	}
	eventBus.emit('connected_account.revocation', {
		...eventOf(record),
		outcome
	});
	return outcome;
}

const inFlight = new Set<Promise<void>>();

/*
 * Revocations a cascade starts and nobody waits for: a deletion is complete once the records are gone, and a
 * provider that does not answer must not hold a request open (FR-025). Bounded per cascade.
 */
function revokeInBackground(
	bucket: UserBucket,
	records: ConnectedAccount[]
): void {
	if (records.length === 0) return;
	const queue = [...records];
	const worker = async () => {
		for (let next = queue.shift(); next; next = queue.shift()) {
			await revokeOne(bucket, next);
		}
	};
	const run = Promise.all(
		Array.from(
			{ length: Math.min(REVOCATIONS_IN_FLIGHT, queue.length) },
			worker
		)
	).then(() => undefined);
	inFlight.add(run);
	void run.finally(() => inFlight.delete(run));
}

/* Test-only: wait for every background revocation started so far. */
export async function revocationsSettled(): Promise<void> {
	while (inFlight.size > 0) await Promise.all([...inFlight]);
}

export type DeletedBy = 'person' | 'administrator' | 'cascade';

/*
 * One account, by its person or an administrator. Deleted first; the person's own disconnect waits for the
 * provider's answer (bounded by the revocation timeout) to tell them, an administrator's does not.
 */
export async function disconnect(input: {
	bucket: UserBucket;
	accountId: string;
	connectedAccountId: string;
	by: 'person' | 'administrator';
}): Promise<{ removed: boolean; revocation?: RevocationOutcome }> {
	const store = getConnectedAccountStore();
	const record = await store.find(input.bucket._id, input.connectedAccountId);
	if (!record || record.accountId !== input.accountId)
		return { removed: false };
	const removed = await store.destroy(input.bucket._id, record._id);
	if (!removed) return { removed: false };
	eventBus.emit('connected_account.deleted', {
		...eventOf(removed),
		by: input.by
	});
	if (input.by === 'person') {
		return {
			removed: true,
			revocation: await revokeOne(
				input.bucket,
				removed,
				REFRESH_BEFORE_REVOKE_MS
			)
		};
	}
	revokeInBackground(input.bucket, [removed]);
	noticeRemoved(input.bucket, [removed], 'removed');
	return { removed: true };
}

function deletedByCascade(records: ConnectedAccount[]): void {
	for (const record of records) {
		eventBus.emit('connected_account.deleted', {
			...eventOf(record),
			by: 'cascade'
		});
	}
}

/* A person deleted (lib/end_users/service.ts `removeEndUser`). A lock never comes here. */
export async function destroyConnectedAccountsOf(
	bucket: UserBucket,
	accountId: string
): Promise<number> {
	const removed = await getConnectedAccountStore().destroyByAccount(
		bucket._id,
		accountId
	);
	deletedByCascade(removed);
	revokeInBackground(bucket, removed);
	return removed.length;
}

/* A service deleted: called with the project as it was before the service left it, so revocation can use it. */
export async function destroyServiceAccounts(
	bucket: UserBucket,
	serviceId: string
): Promise<number> {
	const removed = await getConnectedAccountStore().destroyByService(
		bucket._id,
		serviceId
	);
	deletedByCascade(removed);
	revokeInBackground(bucket, removed);
	/* Only here among the cascades: a deleted person or project has nobody left to tell (specs/118 FR-026). */
	noticeRemoved(bucket, removed, 'service_removed');
	return removed.length;
}

/* A project destroyed (lib/admin/buckets/destroy.ts), before its record is. */
export async function destroyBucketAccounts(
	bucket: UserBucket
): Promise<number> {
	const removed = await getConnectedAccountStore().destroyByBucket(bucket._id);
	deletedByCascade(removed);
	revokeInBackground(bucket, removed);
	return removed.length;
}
