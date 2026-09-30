import { getBucketKeysStore } from '../adapters/index.js';
import type { BucketKey } from '../adapters/types.js';
import { AdminError } from './auth/rbac.js';
import { generateJWKS } from '../helpers/jwks.js';
import type { SupportedAlg } from './jwks/schema.js';
import {
	KEY_PUBLICATION_SECONDS,
	retiredKeyRemovableAt
} from '../keys/issuer_keys.js';

/*
 * The lifecycle every issuer's signing keys follow — the root's and each addressable bucket's: a key is
 * generated published, promoted to sign once every instance has had time to serve it, and retired to
 * keep verifying what it signed until nothing it signed can still be in circulation, after which it is
 * hidden. One implementation, because a divergence between the root's rules and a bucket's would be a
 * defect in whichever was not reviewed.
 *
 * Every instance caches an issuer's set for a short while, and that is what the three steps are written
 * against: a key is published for longer than that cache before it may sign, so no instance signs with
 * a key another does not yet serve (Constitution VI: rotation never invalidates a valid token).
 */

/* Whose keys these are, and the two things that differ between the root and a bucket. */
export interface KeyOwner {
	/* The owner id the records are stored under: a bucket id, or the reserved root owner. */
	readonly id: string;
	/* Written before the change it records; `verb` is generate, promote or retire. */
	audit(verb: 'generate' | 'promote' | 'retire', kid: string): Promise<void>;
	/* Drops this instance's cached set for the owner, so its own write is served at once. */
	invalidate(): void | Promise<void>;
}

/* A refusal carrying what the operator needs to act on it — when to try again, what is in the way. */
export class KeyActionRefused extends AdminError {
	constructor(
		status: number,
		message: string,
		readonly detail: Record<string, unknown>
	) {
		super(status, message);
	}
}

export interface KeyView {
	kid: string;
	kty: string;
	alg: string;
	use: 'sig' | 'enc';
	state: BucketKey['state'];
	createdAt: Date;
	stateChangedAt: Date;
	promotableAt?: Date;
	removableAt?: Date;
}

function promotableAt(key: BucketKey): Date {
	return new Date(
		key.stateChangedAt.getTime() + KEY_PUBLICATION_SECONDS * 1000
	);
}

/* Never the key material: the private members stay on the server, and the public ones are at /jwks. */
function viewOf(key: BucketKey): KeyView {
	return {
		kid: key.kid,
		kty: key.jwk.kty,
		alg: key.alg,
		use: key.use,
		state: key.state,
		createdAt: key.createdAt,
		stateChangedAt: key.stateChangedAt,
		...(key.state === 'published' ? { promotableAt: promotableAt(key) } : {}),
		...(key.state === 'retired'
			? { removableAt: retiredKeyRemovableAt(key) }
			: {})
	};
}

// Hidden is final: a retired key past its window is served by nobody and may not come back.
function visible(key: BucketKey, now: number): boolean {
	return key.state !== 'retired' || now < retiredKeyRemovableAt(key).getTime();
}

async function keyOf(owner: KeyOwner, kid: string): Promise<BucketKey> {
	const key = await getBucketKeysStore().find(owner.id, kid);
	if (!key || !visible(key, Date.now())) {
		throw new AdminError(404, 'no such key');
	}
	return key;
}

/* Built from the stored records rather than a cached set, so it always shows what every instance converges on. */
export async function listKeys(owner: KeyOwner) {
	const now = Date.now();
	const keys = (await getBucketKeysStore().listByBucket(owner.id))
		.filter((key) => visible(key, now))
		.map(viewOf);
	return { keys, publicationSeconds: KEY_PUBLICATION_SECONDS };
}

export async function generateKey(owner: KeyOwner, alg: SupportedAlg) {
	const {
		keys: [jwk]
	} = await generateJWKS(alg);

	await owner.audit('generate', jwk.kid);
	const now = new Date(Date.now());
	const key: BucketKey = {
		_id: `${owner.id} ${jwk.kid}`,
		bucketId: owner.id,
		kid: jwk.kid,
		jwk,
		alg,
		use: 'sig',
		state: 'published',
		createdAt: now,
		stateChangedAt: now
	};
	await getBucketKeysStore().createIfAbsent(key);
	await owner.invalidate();
	return viewOf(key);
}

/*
 * One signing key per algorithm, so which key signs is always answerable: promoting a key returns the one
 * that signed in the same algorithm to `published`, where it keeps verifying what it signed.
 *
 * Per algorithm, not per key type, because every client registers the algorithm it is signed for (OIDC
 * Registration §2) and discovery promises every algorithm it lists — RS256 for one client and PS256 for a
 * FAPI client are both RSA keys, both needed at once. It also means no step can take an algorithm away: a
 * promotion replaces a signer in its own algorithm, and a signer cannot be retired, so an issuer never
 * loses the last key in an algorithm its clients rely on (Constitution VI).
 */
export async function promoteKey(owner: KeyOwner, kid: string) {
	const key = await keyOf(owner, kid);
	if (key.state !== 'published' || key.use !== 'sig') {
		throw new KeyActionRefused(
			409,
			'only a published signing key can be promoted',
			{ reason: 'not_promotable' }
		);
	}
	if (Date.now() < promotableAt(key).getTime()) {
		throw new KeyActionRefused(
			409,
			'the key has not been published long enough for every instance to serve it',
			{ reason: 'too_soon', promotableAt: promotableAt(key) }
		);
	}

	const store = getBucketKeysStore();
	const all = await store.listByBucket(owner.id);
	const displaced = all.find(
		(other) =>
			other.state === 'signing' &&
			other.use === 'sig' &&
			other.alg === key.alg &&
			other.kid !== key.kid
	);

	await owner.audit('promote', key.kid);
	const now = new Date(Date.now());
	/*
	 * The new signer first, then the displaced one back to published: in between the algorithm has two
	 * signers, never none, and either one signs a token every instance can verify.
	 */
	await store.setState(owner.id, key.kid, 'signing', now);
	if (displaced) {
		await store.setState(owner.id, displaced.kid, 'published', now);
	}
	await owner.invalidate();
	return {
		kid: key.kid,
		state: 'signing' as const,
		...(displaced ? { demoted: displaced.kid } : {})
	};
}

/*
 * Retirement ends a key: once its window closes nothing it signed verifies again. So the caller must name
 * the key it means — the console asks the operator to type it — and a request that does not is refused
 * before anything is recorded.
 */
export async function retireKey(
	owner: KeyOwner,
	kid: string,
	confirm: unknown
) {
	if (confirm !== kid) {
		throw new KeyActionRefused(
			422,
			'confirm retirement by naming the key: send { "confirm": "<kid>" }',
			{ reason: 'confirmation_mismatch' }
		);
	}
	const key = await keyOf(owner, kid);
	if (key.state === 'signing') {
		throw new KeyActionRefused(
			409,
			'this key signs; promote another key in its algorithm first',
			{ reason: 'signing_key' }
		);
	}
	if (key.state === 'retired') {
		throw new KeyActionRefused(409, 'the key is already retired', {
			reason: 'already_retired'
		});
	}

	await owner.audit('retire', key.kid);
	const retired = await getBucketKeysStore().setState(
		owner.id,
		key.kid,
		'retired',
		new Date(Date.now())
	);
	await owner.invalidate();
	if (!retired) throw new AdminError(404, 'no such key');
	return {
		kid: key.kid,
		state: 'retired' as const,
		removableAt: retiredKeyRemovableAt(retired)
	};
}
