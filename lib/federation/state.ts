import crypto from 'crypto';

import { adapter } from '../adapters/index.js';
import epochTime from '../helpers/epoch_time.js';
import { HANDOFF_TTL_SECONDS, STATE_TTL_SECONDS } from './consts.js';
import type { FederationStatePayload } from './types.js';

/*
 * The two-stage round-trip record. This module owns both the secrets and their storage, deliberately:
 * "the live value is never at rest" is a property of one file rather than a rule every caller has to
 * remember.
 *
 * Stage one is written when a user leaves for the upstream provider and holds what the callback needs to
 * finish the exchange. Stage two replaces it once an identity has been established and holds only the
 * interaction and the account — a single-use handoff, because the state value must not appear in a URL
 * after the callback.
 */

function records() {
	return adapter('FederationState');
}

/* 32 bytes of uniform randomness: the same size the admin console's own outbound flow uses. */
function secret(): string {
	return crypto.randomBytes(32).toString('base64url');
}

/*
 * The record id. Unsalted SHA-256 is right here for the reason lib/password_reset/challenge.ts records
 * about its own token: the input is 256 bits of uniform randomness, so there is nothing to brute-force
 * and nothing to rainbow-table — and a salted digest could not be derived from the value alone, which is
 * what keeps the lookup a point read instead of a scan.
 */
function idFor(value: string): string {
	return crypto.createHash('sha256').update(value).digest('hex');
}

export interface PendingStart {
	interactionUid: string;
	bucketId: string;
	providerId: string;
	/* Omitted when the upstream advertises no S256, in which case no PKCE is sent. */
	withPkce: boolean;
}

export interface PendingSecrets {
	state: string;
	nonce: string;
	codeVerifier?: string;
}

/*
 * Open a round trip. Returns the values the authorization request carries; none of them is stored, and
 * the caller must not log them either.
 */
export async function openPending(
	start: PendingStart
): Promise<PendingSecrets> {
	const state = secret();
	const nonce = secret();
	const codeVerifier = start.withPkce ? secret() : undefined;

	await records().upsert(
		idFor(state),
		{
			stage: 'pending',
			interactionUid: start.interactionUid,
			bucketId: start.bucketId,
			providerId: start.providerId,
			nonce,
			...(codeVerifier ? { codeVerifier } : {}),
			exp: epochTime() + STATE_TTL_SECONDS
		},
		STATE_TTL_SECONDS
	);

	return { state, nonce, codeVerifier };
}

/*
 * Spend a round trip. Destroyed before the caller acts on it, so a replay arriving mid-flight finds
 * nothing rather than racing the sign-in.
 *
 * `exp` is compared here as well as being reaped by the store, following the same departure the password
 * reset made: MongoDB's TTL monitor deletes lazily — a record can outlive its expiry by a minute or more
 * under load — and for a value that completes a sign-in, that is a minute of validity nobody granted.
 */
export async function consumePending(
	state: string
): Promise<FederationStatePayload | null> {
	const id = idFor(state);
	const record = await records().find(id);
	if (!record || record.stage !== 'pending') {
		return null;
	}

	await records().destroy(id);

	if (record.exp <= epochTime()) {
		return null;
	}
	return record;
}

/*
 * Hand the resolved account back into the interaction. A fresh value rather than a reuse of `state`: the
 * state has just been spent, and a URL the browser is about to follow should not carry a value that ever
 * authorised the exchange.
 */
export async function openHandoff(handoff: {
	interactionUid: string;
	accountId: string;
}): Promise<string> {
	const ref = secret();
	await records().upsert(
		idFor(ref),
		{
			stage: 'complete',
			interactionUid: handoff.interactionUid,
			accountId: handoff.accountId,
			exp: epochTime() + HANDOFF_TTL_SECONDS
		},
		HANDOFF_TTL_SECONDS
	);
	return ref;
}

/*
 * Spend the handoff, refusing one that belongs to a different interaction.
 *
 * The `interactionUid` comparison is the reason this takes the uid rather than trusting the record: the
 * `ref` travels in a URL, so without it a leaked handoff could be spent inside any interaction the
 * holder happened to have a cookie for — signing them in as somebody else.
 */
export async function consumeHandoff(
	ref: string,
	interactionUid: string
): Promise<FederationStatePayload | null> {
	const id = idFor(ref);
	const record = await records().find(id);
	if (!record || record.stage !== 'complete') {
		return null;
	}

	await records().destroy(id);

	if (record.exp <= epochTime()) {
		return null;
	}
	if (record.interactionUid !== interactionUid) {
		return null;
	}
	return record;
}
