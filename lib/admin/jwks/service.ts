import { jwksStore } from '../../adapters/index.js';
import {
	keystore,
	publicJWKS,
	toPublicJwk,
	type PublicJWK
} from '../../configs/keystore.js';
import { generateJWKS } from '../../helpers/jwks.js';
import { type UnnormalizedJWK } from '../../configs/verifyJWKs.js';
import { recordAdminAudit } from '../audit/record.js';
import { AdminError, type AdminContext } from '../auth/rbac.js';

// RSA signing algorithms offered for generation. Matches what generateJWKS produces; EC/OKP
// and encryption-use keys are out of scope for SP-5 (they may still exist in the store if
// provisioned out of band, and are displayed/removable).
const SUPPORTED_ALGS = ['RS256', 'RS384', 'RS512'] as const;
type SupportedAlg = (typeof SUPPORTED_ALGS)[number];

export type KeyStatus = 'active' | 'pending activation' | 'pending removal';

// The admin view of a key is the same client-safe projection the server publishes at /jwks
// (configs/keystore.ts owns it): an explicit allow-list, never a blocklist, so an unforeseen
// private component (d/p/q/dp/dq/qi/oth) can never leak into an admin response either.
export type KeyView = PublicJWK & { status: KeyStatus };

export interface JwksState {
	keys: KeyView[];
	restartRequired: boolean;
	changedKeys: string[];
	supportedAlgorithms: string[];
}

// A key counts as a signing key by its published `use` — explicit, else inferred from `alg`, by
// the one projection that owns that inference. Used to enforce "at least one signing key must
// remain".
function isSigningKey(key: UnnormalizedJWK): boolean {
	return toPublicJwk(key).use === 'sig';
}

// The keys the server currently serves at /jwks (the live set — reflects hot-applied keys
// immediately). The desired set is the persisted jwksStore. Drift between the two drives status
// and the restart-required indicator; because generation hot-applies, the only drift in practice
// is a deleted key that is still live until the next restart (pending removal).
export async function getJwksState(): Promise<JwksState> {
	// Both sides are projected before anything is compared. The live keys already are projections;
	// the store's are raw, and a key an operator provisioned without a `kid` only gets one derived
	// by the projection. Comparing raw kids would compare `undefined` against a real kid, so such a
	// key could never match its live counterpart, and it would report `undefined` as a changed kid.
	const desired = (await jwksStore.getAll()).map(toPublicJwk);
	const running = publicJWKS.keys;
	const desiredKids = new Set(desired.map((k) => k.kid));
	const runningKids = new Set(running.map((k) => k.kid));

	const keys: KeyView[] = [];
	const changedKeys: string[] = [];

	for (const key of desired) {
		if (runningKids.has(key.kid)) {
			keys.push({ ...key, status: 'active' });
		} else {
			keys.push({ ...key, status: 'pending activation' });
			changedKeys.push(key.kid);
		}
	}
	for (const key of running) {
		if (!desiredKids.has(key.kid)) {
			keys.push({ ...key, status: 'pending removal' });
			changedKeys.push(key.kid);
		}
	}

	return {
		keys,
		restartRequired: changedKeys.length > 0,
		changedKeys,
		supportedAlgorithms: [...SUPPORTED_ALGS]
	};
}

// Generate a new RSA signing key, persist it, and hot-apply it to the live keystore so it is
// usable immediately — no restart. Audit-first: the audit entry is written before any state
// change, so a failed audit write aborts before a key is created. The key is added at the END
// of the keystore, so the existing key keeps signing (publish-for-verification-only); a later
// rotation makes the new key the signer by removing the old one.
export async function generateKey(
	ctx: AdminContext,
	alg: unknown
): Promise<JwksState> {
	if (
		typeof alg !== 'string' ||
		!SUPPORTED_ALGS.includes(alg as SupportedAlg)
	) {
		throw new AdminError(
			422,
			`unsupported algorithm; expected one of: ${SUPPORTED_ALGS.join(', ')}`
		);
	}
	const {
		keys: [key]
	} = await generateJWKS(alg as SupportedAlg);
	const { kid } = key;
	await recordAdminAudit(ctx, 'jwks.generate', 'jwks', kid);
	await jwksStore.set(kid, key);

	// Mutated in place: every module holds the same imported keystore/publicJWKS reference.
	keystore.add(structuredClone(key));
	publicJWKS.keys.push(toPublicJwk(key));

	return getJwksState();
}

// Remove a key from the store. Refuses (404) a kid not present in the store, and (422) any
// removal that would leave the desired set with no signing key. Audit-first, as above.
//
// Removal is NOT hot-applied: the server keeps serving and honoring the key until the next
// restart (status: pending removal). Dropping a key from the live /jwks would break
// verification of tokens already signed with it (constitution VI — rotation must not invalidate
// valid tokens), so retirement stays a deliberate, restart-gated step.
export async function deleteKey(
	ctx: AdminContext,
	kid: string
): Promise<JwksState> {
	const desired = await jwksStore.getAll();
	// Matched on the key's own `kid`, deliberately not the projected one: that field *is* the
	// store's identity for a key (both adapters address keys by it), so a key carrying no `kid`
	// is not addressable and must 404 rather than be reported deleted after a no-op.
	if (!desired.some((k) => k.kid === kid)) {
		throw new AdminError(404, `no such key: ${kid}`);
	}
	const remainingSigning = desired.filter(
		(k) => k.kid !== kid && isSigningKey(k)
	).length;
	if (remainingSigning === 0) {
		throw new AdminError(422, 'at least one signing key must remain');
	}
	await recordAdminAudit(ctx, 'jwks.delete', 'jwks', kid);
	await jwksStore.delete(kid);
	return getJwksState();
}
