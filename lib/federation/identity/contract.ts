import type { RequestBucket } from '../../configs/issuer.js';
import type { FederationProvider } from '../types.js';

/*
 * What the two identity protocols agree on, in a module that imports neither of them.
 *
 * Separate from ./index.ts on purpose: the readers need the error class and the types, and ./index.ts
 * needs the readers. Putting both in one file is a cycle, and this repository has been bitten by one
 * before — `base_model → provider → models` reorders module evaluation and fails somewhere unrelated.
 */

export interface UpstreamIdentity {
	subject: string;
	claims: Record<string, unknown>;
}

/*
 * Which of the two answers the route should give, carried rather than decided here: the route owns the
 * pages and the events, and it answered these two ways long before there was a seam.
 *
 * `upstream` means the other side is broken or unreachable; `rejected` means what came back cannot be
 * trusted. The same distinction `DiscoveryError` and `FederationIdTokenRejected` already drew.
 */
export type IdentityStage = 'upstream' | 'rejected';

export class IdentityError extends Error {
	readonly stage: IdentityStage;
	readonly reason: string;

	constructor(stage: IdentityStage, reason: string) {
		super(`upstream identity: ${stage} (${reason})`);
		this.stage = stage;
		this.reason = reason;
	}
}

export interface IdentityRequest {
	provider: FederationProvider;
	code: string;
	bucket: RequestBucket;
	/* Bound to this attempt. Compared against the assertion where there is one to compare it against. */
	nonce: string;
	codeVerifier?: string;
}
