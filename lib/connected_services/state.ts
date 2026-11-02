import crypto from 'crypto';

import { checkedAdapter } from '../adapters/index.js';
import epochTime from '../helpers/epoch_time.js';
import { ConnectStatePayload } from './types.js';

/*
 * A connect flow's round-trip record (specs/117 R5). As in lib/federation/state.ts, this module owns both the
 * secrets and their storage, so "the live value is never at rest" is a property of one file.
 */

/* The same wait as a federated sign-in: a person typing a password into someone else's page. */
export const CONNECT_STATE_TTL_SECONDS = 600;

function records() {
	return checkedAdapter('ConnectState', ConnectStatePayload);
}

function secret(): string {
	return crypto.randomBytes(32).toString('base64url');
}

/* Unsalted SHA-256 of 256 random bits, for the reason lib/federation/state.ts gives: a point read, nothing to guess. */
export function digestOf(value: string): string {
	return crypto.createHash('sha256').update(value).digest('hex');
}

export interface ConnectStart {
	bucketId: string;
	serviceId: string;
	accountId: string;
	/* The session id that starts the flow; only its digest is stored. */
	sessionId: string;
	withPkce: boolean;
	withNonce: boolean;
	requestedScopes: string[];
}

export interface ConnectSecrets {
	state: string;
	nonce?: string;
	codeChallenge?: string;
}

export async function openConnect(
	start: ConnectStart
): Promise<ConnectSecrets> {
	const state = secret();
	const nonce = start.withNonce ? secret() : undefined;
	const verifier = start.withPkce ? secret() : undefined;
	await records().upsert(
		digestOf(state),
		{
			bucketId: start.bucketId,
			serviceId: start.serviceId,
			accountId: start.accountId,
			sessionDigest: digestOf(start.sessionId),
			...(verifier ? { verifier } : {}),
			...(nonce ? { nonce } : {}),
			requestedScopes: start.requestedScopes,
			exp: epochTime() + CONNECT_STATE_TTL_SECONDS
		},
		CONNECT_STATE_TTL_SECONDS
	);
	return {
		state,
		...(nonce ? { nonce } : {}),
		...(verifier
			? {
					codeChallenge: crypto
						.createHash('sha256')
						.update(verifier)
						.digest('base64url')
				}
			: {})
	};
}

/*
 * Spends a flow: destroyed before anything acts on it, so a replay finds nothing, and expiry compared here as
 * well as reaped, because a datastore's reaper runs late.
 */
export async function spendConnect(
	state: string
): Promise<ConnectStatePayload | null> {
	const id = digestOf(state);
	const record = await records().find(id);
	if (!record) return null;
	await records().destroy(id);
	return record.exp > epochTime() ? record : null;
}
