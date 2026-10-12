import {
	getBucketStore,
	getProvisioningConnectionStore
} from '../adapters/index.js';
import type { UserBucket } from '../adapters/types.js';
import { issuingBucket } from '../admin/auth/bucketAddress.js';
import { isScheduledForDeletion } from '../consts/bucket_deletion.js';
import { stabilityOf } from '../admin/federation/guidance.js';
import { canSignIn } from '../end_users/can_sign_in.js';
import { IdentityError, identityFor } from './identity/index.js';
import { tryExpiredPage, tryFinishedPage } from './pages.js';
import { federationEnabled } from './providers.js';
import { decideFederatedAccount, type Decision } from './resolve.js';
import { finishTry } from './state.js';
import type {
	FederationProvider,
	FederationStatePayload,
	TryResult
} from './types.js';

/*
 * The return leg of a try of a provider (specs/088 R5, R6): the same exchange and the same decision ladder as a
 * sign-in, stopped before anything is written.
 *
 * The callback reaches here only when the record it spent says the round trip is a try — the request has no
 * say in it. From then on nothing a sign-in writes is written: no account, no link, no pending link, no
 * handoff, no session, no administrator registration, no sign-in activity, no upstream session record. The
 * one write is the result, into the try record the starting console session polls.
 *
 * The provider is looked up whether or not it is enabled — trying one before switching it on is the point —
 * which is safe because no sign-in follows from here; every real sign-in still goes through
 * `findEnabledProvider`. The deployment switch still applies: with federation off there is nothing to try.
 */

/* Claims that describe the exchange rather than the person, and so mean nothing to the administrator. */
const EXCHANGE_CLAIMS = new Set(['nonce', 'at_hash', 'c_hash']);

/* A provider's own error text is shown to the administrator who started the try, bounded. */
const DESCRIPTION_LIMIT = 500;

export interface TryReturnParams {
	code?: string;
	iss?: string;
	error?: string;
	error_description?: string;
}

export async function completeTry(
	pending: FederationStatePayload,
	params: TryReturnParams
): Promise<Response> {
	const { tryId, bucketId, providerId, nonce } = pending;
	if (!tryId || !bucketId || !providerId || !nonce) return tryExpiredPage();

	const found = await getBucketStore().find(bucketId);
	/* A bucket scheduled for deletion since the try began is answered as gone (specs/090), as its callback is. */
	const bucket = found && !isScheduledForDeletion(found) ? found : null;
	const provider = bucket?.federation.find((p) => p.id === providerId);
	const base = {
		providerEnabled: provider?.enabled === true,
		callbackProvisional: bucket ? stabilityOf(bucket) === 'provisional' : false
	};

	const result = await (async (): Promise<TryResult> => {
		if (!bucket || !provider) {
			return {
				...base,
				error: { stage: 'rejected', reason: 'provider_removed' }
			};
		}
		if (!federationEnabled()) {
			return {
				...base,
				error: { stage: 'rejected', reason: 'federation_off' }
			};
		}
		if (params.error) {
			return {
				...base,
				error: {
					stage: 'declined',
					reason: params.error.slice(0, DESCRIPTION_LIMIT),
					...(params.error_description
						? {
								description: params.error_description.slice(
									0,
									DESCRIPTION_LIMIT
								)
							}
						: {})
				}
			};
		}
		if (!params.code) {
			return { ...base, error: { stage: 'rejected', reason: 'no_code' } };
		}

		let identity;
		try {
			identity = await identityFor({
				provider,
				code: params.code,
				bucket: await issuingBucket(bucketId),
				nonce,
				codeVerifier: pending.codeVerifier,
				iss: params.iss
			});
		} catch (err) {
			if (err instanceof IdentityError) {
				return { ...base, error: { stage: err.stage, reason: err.reason } };
			}
			throw err;
		}

		const decision = await decideFederatedAccount({
			bucket,
			provider,
			subject: identity.subject,
			claims: identity.claims
		});
		return {
			...base,
			answer: answerOf(provider, identity.subject, identity.claims),
			outcome: await outcomeOf(bucket, decision)
		};
	})();

	return (await finishTry(tryId, result))
		? tryFinishedPage()
		: tryExpiredPage();
}

function answerOf(
	provider: FederationProvider,
	subject: string,
	claims: Record<string, unknown>
): NonNullable<TryResult['answer']> {
	const email = claims[provider.emailClaim];
	const verified = claims.email_verified;
	return {
		subject,
		...(typeof email === 'string' && email ? { email } : {}),
		...(typeof verified === 'boolean' ? { emailVerified: verified } : {}),
		claims: Object.fromEntries(
			Object.entries(claims).filter(([name]) => !EXCHANGE_CLAIMS.has(name))
		)
	};
}

function accountOf(account: { _id: string; email: string }) {
	return {
		id: account._id,
		...(account.email ? { email: account.email } : {})
	};
}

async function connectionOf(bucket: UserBucket, connectionId: string) {
	const connection = await getProvisioningConnectionStore().find(connectionId);
	return connection && connection.bucketId === bucket._id
		? { id: connection._id, displayName: connection.displayName }
		: { id: connectionId, displayName: connectionId };
}

/*
 * What a real sign-in would do now, in the words the console shows. A link through the directory's
 * correlation rule is reported as the match it is; one to an account that could not sign in afterwards is
 * reported as the refusal a sign-in would end in, naming the account.
 */
async function outcomeOf(
	bucket: UserBucket,
	decision: Decision
): Promise<NonNullable<TryResult['outcome']>> {
	switch (decision.kind) {
		case 'signin':
			return { kind: 'signin', account: accountOf(decision.account) };
		case 'refuse':
			return {
				kind: 'refuse',
				reason: decision.reason,
				...(decision.account ? { account: accountOf(decision.account) } : {})
			};
		case 'conflict':
			return {
				kind: 'conflict',
				reason: 'link_conflict',
				account: accountOf(decision.account),
				connection: await connectionOf(bucket, decision.connectionId)
			};
		case 'password_required':
			return {
				kind: 'password_required',
				account: accountOf(decision.account)
			};
		case 'link': {
			if (decision.via === 'email') {
				return { kind: 'link', account: accountOf(decision.account) };
			}
			const connection = decision.connectionId
				? await connectionOf(bucket, decision.connectionId)
				: undefined;
			return canSignIn(decision.account)
				? {
						kind: 'correlate',
						account: accountOf(decision.account),
						...(connection ? { connection } : {})
					}
				: {
						kind: 'refuse',
						reason: 'inactive',
						account: accountOf(decision.account),
						...(connection ? { connection } : {})
					};
		}
		case 'provision':
			return { kind: 'provision', verified: decision.verified };
	}
}
