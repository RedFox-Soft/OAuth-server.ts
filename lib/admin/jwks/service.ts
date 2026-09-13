import { jwksStore } from '../../adapters/index.js';
import {
	keystore,
	publicJWKS,
	toPublicJwk,
	type PublicJWK
} from '../../configs/keystore.js';
import { generateJWKS } from '../../helpers/jwks.js';
import {
	getAlgorithm,
	type UnnormalizedJWK
} from '../../configs/verifyJWKs.js';
import { JWKS_KEYS } from '../../configs/keys.js';
import { recordAdminAudit } from '../audit/record.js';
import { AdminError, type AdminContext } from '../auth/rbac.js';

// The generation allow-list now lives in ./schema.ts, so the MCP tool catalogue can describe the
// same set without importing this module (which reaches the adapters, and from there a db module
// that connects at import time). Re-exported here because callers of the service used to read it.
import { SUPPORTED_ALGS, type SupportedAlg } from './schema.js';

export { SUPPORTED_ALGS, type SupportedAlg };

export type KeyStatus = 'active' | 'pending activation' | 'pending removal';

// The admin view of a key is the same client-safe projection the server publishes at /jwks
// (configs/keystore.ts owns it): an explicit allow-list, never a blocklist, so an unforeseen
// private component (d/p/q/dp/dq/qi/oth) can never leak into an admin response either.
export type KeyView = PublicJWK & { status: KeyStatus };

export interface JwksState {
	keys: KeyView[];
	restartRequired: boolean;
	changedKeys: string[];
	/* Signing algorithms present in the store that the running server does not advertise yet. */
	unadvertisedAlgorithms: string[];
	supportedAlgorithms: string[];
}

/*
 * The signing algorithms the running server tells clients it supports.
 *
 * Derived at module load from the boot key set (`lib/configs/jwaAlgorithms.ts`) and published in the
 * discovery document, which means it does NOT follow a key generated since — generation hot-applies a
 * key for *signing*, but nothing recomputes what discovery advertises.
 *
 * That gap is why this is measured rather than assumed. An operator who generates the ES256 key a
 * FAPI 2.0 deployment needs, and is told no restart is required, has a server that can sign ES256 and
 * a discovery document that never mentions it — so no client ever asks. The same boot snapshot the
 * advertisement is built from is read here, so the comparison cannot drift from the claim.
 */
function advertisedSigningAlgorithms(): Set<string> {
	return new Set(getAlgorithm(JWKS_KEYS).sign);
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

	/*
	 * A signing algorithm reaches clients only once discovery names it, and discovery is built from
	 * the boot key set — so a key whose algorithm is new to this server is not usable by anybody until
	 * a restart, however live it is for signing. Reported beside the key drift rather than folded into
	 * it because the remedy is the same (restart) but the reason is not, and an operator told only
	 * "restart required" would look for a pending key and find none.
	 */
	const advertised = advertisedSigningAlgorithms();
	const unadvertisedAlgorithms = [
		...new Set(
			keys
				.filter((k) => k.use === 'sig' && k.status !== 'pending removal')
				.map((k) => k.alg)
				.filter((alg) => !advertised.has(alg))
		)
	];

	return {
		keys,
		restartRequired:
			changedKeys.length > 0 || unadvertisedAlgorithms.length > 0,
		changedKeys,
		unadvertisedAlgorithms,
		supportedAlgorithms: [...SUPPORTED_ALGS]
	};
}

// Generate a new asymmetric signing key, persist it, and hot-apply it to the live keystore so it
// can sign immediately. A key whose algorithm this server did not boot with still needs a restart
// before discovery advertises it, which getJwksState reports. Audit-first: the audit entry is
// written before any state change, so a failed audit write aborts before a key is created. The key
// is added at the END of the keystore, so the existing key keeps signing
// (publish-for-verification-only); a later rotation makes the new key the signer by removing the
// old one.
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
	await recordAdminAudit(ctx, 'jwks.generate', kid);
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
	await recordAdminAudit(ctx, 'jwks.delete', kid);
	await jwksStore.delete(kid);
	return getJwksState();
}
