import { getBucketKeysStore } from '../adapters/index.js';
import type { BucketKey } from '../adapters/types.js';
import { AdminError } from './auth/rbac.js';
import { generateJWKS } from '../helpers/jwks.js';
import { SUPPORTED_ALGS, type SupportedAlg } from './jwks/schema.js';
import {
	KEY_PUBLICATION_SECONDS,
	RETIRED_KEY_LIFETIME_SECONDS,
	retiredKeyRemovableAt
} from '../keys/issuer_keys.js';

/*
 * The lifecycle every issuer's signing keys follow — the root's and each addressable bucket's: a key is
 * generated published, promoted to sign once every instance has had time to serve it, and retired to
 * keep verifying what it signed until nothing it signed can still be in circulation, after which it is
 * hidden. Rotation is promote-the-ready-key and generate-the-next in one act; revocation hides a key at
 * once, for a key that may be compromised (specs/087). One implementation, because a divergence between
 * the root's rules and a bucket's would be a defect in whichever was not reviewed.
 *
 * Every instance caches an issuer's set for a short while, and that is what the steps are written
 * against: a key is published for longer than that cache before it may sign, so no instance signs with
 * a key another does not yet serve (Constitution VI: rotation never invalidates a valid token). Revoking
 * a signer with no ready replacement is the one step that does not wait — see `revokeKey`.
 */

export type KeyVerb = 'generate' | 'promote' | 'retire' | 'rotate' | 'revoke';

/* Whose keys these are, and the two things that differ between the root and a bucket. */
export interface KeyOwner {
	/* The owner id the records are stored under: a bucket id, or the reserved root owner. */
	readonly id: string;
	/*
	 * Written before the change it records. `kid` is the key the act is about; `keys` names every key a
	 * rotation or revocation touched, by role, so one entry records the whole act.
	 */
	audit(
		verb: KeyVerb,
		kid: string,
		keys?: Record<string, string>
	): Promise<void>;
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
	/* When a published key stopped signing (specs/086); absent if it never signed. */
	signedUntil?: Date;
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
		/*
		 * Derived rather than stored: a published key's state time moves only when a promotion demotes it, since
		 * generating sets both times to one instant and the publication window keeps a promotion from landing on
		 * it. A retired key has lost the time — retiring overwrites it — so it states none.
		 */
		...(key.state === 'published' &&
		key.stateChangedAt.getTime() > key.createdAt.getTime()
			? { signedUntil: key.stateChangedAt }
			: {}),
		...(key.state === 'retired'
			? { removableAt: retiredKeyRemovableAt(key) }
			: {})
	};
}

/*
 * Hidden is final: a retired key past its window, and a revoked key from the moment it was revoked, is
 * served by nobody and may not come back.
 */
function visible(key: BucketKey, now: number): boolean {
	if (key.state === 'revoked') return false;
	return key.state !== 'retired' || now < retiredKeyRemovableAt(key).getTime();
}

/*
 * How many keys an owner may hold and make (specs/103). Generating a key is the most expensive thing a tenant can
 * ask of the processor every tenant shares — an RSA key pair costs real time — and each key is stored and published
 * for good, growing the set every client fetches. One signer and one published key for each algorithm, with the
 * retired ones still verifying, stays well under the first bound.
 *
 * The second counts revoked keys too, because revoking a signer generates its replacement: without it, generating
 * and revoking in a loop would make keys without limit while never holding more than a few.
 */
export const MAX_HELD_KEYS = 12;
export const MAX_KEYS_PER_DAY = 20;
const DAY_MS = 86_400_000;

function assertKeyRoom(
	all: readonly BucketKey[],
	{ adds }: { adds: boolean }
): void {
	const now = Date.now();
	if (adds && all.filter((key) => visible(key, now)).length >= MAX_HELD_KEYS) {
		throw new KeyActionRefused(
			409,
			`${String(MAX_HELD_KEYS)} keys are already held: retire one before adding another`,
			{ reason: 'key_limit' }
		);
	}
	if (
		all.filter((key) => now - key.createdAt.getTime() < DAY_MS).length >=
		MAX_KEYS_PER_DAY
	) {
		throw new KeyActionRefused(
			409,
			`${String(MAX_KEYS_PER_DAY)} keys were made here in the last day: try again later`,
			{ reason: 'key_limit' }
		);
	}
}

async function keyOf(owner: KeyOwner, kid: string): Promise<BucketKey> {
	const key = await getBucketKeysStore().find(owner.id, kid);
	if (!key || !visible(key, Date.now())) {
		throw new AdminError(404, 'no such key');
	}
	return key;
}

/* May sign now: published, a signing key of the algorithm, and served by every instance for long enough. */
function ready(key: BucketKey, alg: string, now: number): boolean {
	return (
		key.state === 'published' &&
		key.use === 'sig' &&
		key.alg === alg &&
		promotableAt(key).getTime() <= now
	);
}

/*
 * The oldest ready key, because it is the one every relying party has had longest to fetch. Ties on the
 * creation time are broken by kid, so two instances rotating at once promote the same key.
 */
function oldestReady(
	keys: readonly BucketKey[],
	alg: string,
	now: number,
	except?: string
): BucketKey | undefined {
	return keys
		.filter((key) => key.kid !== except && ready(key, alg, now))
		.sort(
			(a, b) =>
				a.createdAt.getTime() - b.createdAt.getTime() ||
				a.kid.localeCompare(b.kid)
		)
		.at(0);
}

function signerOf(
	keys: readonly BucketKey[],
	alg: string,
	except: string
): BucketKey | undefined {
	return keys.find(
		(other) =>
			other.state === 'signing' &&
			other.use === 'sig' &&
			other.alg === alg &&
			other.kid !== except
	);
}

async function freshJwk(alg: SupportedAlg) {
	const {
		keys: [jwk]
	} = await generateJWKS(alg);
	return jwk;
}

function recordOf(
	owner: KeyOwner,
	jwk: Awaited<ReturnType<typeof freshJwk>>,
	alg: SupportedAlg,
	state: BucketKey['state'],
	at: Date
): BucketKey {
	return {
		_id: `${owner.id} ${jwk.kid}`,
		bucketId: owner.id,
		kid: jwk.kid,
		jwk,
		alg,
		use: 'sig',
		state,
		createdAt: at,
		stateChangedAt: at
	};
}

function isSupportedAlg(alg: string): alg is SupportedAlg {
	return (SUPPORTED_ALGS as readonly string[]).includes(alg);
}

/* Built from the stored records rather than a cached set, so it always shows what every instance converges on. */
export async function listKeys(owner: KeyOwner) {
	const now = Date.now();
	const keys = (await getBucketKeysStore().listByBucket(owner.id))
		.filter((key) => visible(key, now))
		.map(viewOf);
	// The retired-key lifetime lets the console say when a key it is about to retire stops verifying.
	return {
		keys,
		publicationSeconds: KEY_PUBLICATION_SECONDS,
		retiredKeyLifetimeSeconds: RETIRED_KEY_LIFETIME_SECONDS
	};
}

export async function generateKey(owner: KeyOwner, alg: SupportedAlg) {
	assertKeyRoom(await getBucketKeysStore().listByBucket(owner.id), {
		adds: true
	});
	const jwk = await freshJwk(alg);

	await owner.audit('generate', jwk.kid);
	const key = recordOf(owner, jwk, alg, 'published', new Date(Date.now()));
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
 * promotion replaces a signer in its own algorithm, a signer cannot be retired, and revoking one puts
 * another in its place, so an issuer never loses the last key in an algorithm its clients rely on
 * (Constitution VI).
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
	const displaced = signerOf(
		await store.listByBucket(owner.id),
		key.alg,
		key.kid
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
 * Rotation in one act (specs/087): the oldest published key of the algorithm that may sign now does, the
 * algorithm's signer returns to published where it keeps verifying what it signed, and a new key is
 * generated published — so the next rotation always has a key every relying party has already fetched.
 * With no key ready, only the next key is generated, and the answer says from when the algorithm can
 * rotate. Nothing is ever promoted inside its publication window, which is what made the manual procedure
 * easy to get wrong.
 *
 * Two rotations at once promote the same key (the choice is deterministic, the write idempotent) and
 * each generates a next key; two next keys is harmless, and the new signer is written before the old one
 * is demoted, so there is never a moment without one.
 */
export async function rotateKey(owner: KeyOwner, alg: SupportedAlg) {
	const store = getBucketKeysStore();
	const all = await store.listByBucket(owner.id);
	const now = Date.now();
	const next = oldestReady(all, alg, now);
	const displaced = next ? signerOf(all, alg, next.kid) : undefined;
	assertKeyRoom(all, { adds: true });
	// Generated before the audit entry, so the entry can name it; stored after, as generation is.
	const jwk = await freshJwk(alg);

	await owner.audit('rotate', next?.kid ?? jwk.kid, {
		...(next ? { promoted: next.kid } : {}),
		...(displaced ? { demoted: displaced.kid } : {}),
		generated: jwk.kid
	});
	const at = new Date(Date.now());
	if (next) {
		await store.setState(owner.id, next.kid, 'signing', at);
		if (displaced) {
			await store.setState(owner.id, displaced.kid, 'published', at);
		}
	}
	const generated = recordOf(owner, jwk, alg, 'published', at);
	await store.createIfAbsent(generated);
	await owner.invalidate();

	/*
	 * When nothing was promoted, the earliest any key of the algorithm may sign — a key generated earlier
	 * and still inside its window comes before the one just made.
	 */
	const rotatableAt = next
		? undefined
		: new Date(
				Math.min(
					promotableAt(generated).getTime(),
					...all
						.filter(
							(key) =>
								key.state === 'published' &&
								key.use === 'sig' &&
								key.alg === alg
						)
						.map((key) => promotableAt(key).getTime())
				)
			);
	return {
		alg,
		...(next ? { promoted: next.kid } : {}),
		...(displaced ? { demoted: displaced.kid } : {}),
		generated: jwk.kid,
		...(rotatableAt ? { rotatableAt } : {})
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

/*
 * Revocation is the answer to a key that may be compromised (specs/087): retiring leaves a key verifying
 * for a day, which for a leaked key is a day in which forged tokens verify. A revoked key leaves the key
 * set and every verification at once — on this instance now, on every other within the key cache bound —
 * and its record is kept, so the trail's references resolve and its kid is never reused. Named by the
 * caller, as a retirement is, because it cannot be undone.
 *
 * Revoking the signer puts another key in its place in the same act, so no algorithm that had a signer is
 * left without one: the oldest ready key of the algorithm, or else a newly generated key that signs at
 * once. That one skips the publication window — a relying party holding a cached key set may reject new
 * tokens until it refreshes — which is the price of ending a compromised key now rather than in a minute.
 */
export async function revokeKey(
	owner: KeyOwner,
	kid: string,
	confirm: unknown
) {
	if (confirm !== kid) {
		throw new KeyActionRefused(
			422,
			'confirm revocation by naming the key: send { "confirm": "<kid>" }',
			{ reason: 'confirmation_mismatch' }
		);
	}
	const store = getBucketKeysStore();
	const key = await store.find(owner.id, kid);
	if (key?.state === 'revoked') {
		throw new KeyActionRefused(409, 'the key is already revoked', {
			reason: 'already_revoked'
		});
	}
	if (!key || !visible(key, Date.now())) {
		throw new AdminError(404, 'no such key');
	}

	const signs = key.state === 'signing' && key.use === 'sig';
	const held = await store.listByBucket(owner.id);
	const standby = signs
		? oldestReady(held, key.alg, Date.now(), kid)
		: undefined;
	// A replacement is generated only when no published key can take over; that one counts against the day.
	if (signs && !standby) assertKeyRoom(held, { adds: false });
	let fresh:
		| { jwk: Awaited<ReturnType<typeof freshJwk>>; alg: SupportedAlg }
		| undefined;
	if (signs && !standby) {
		if (!isSupportedAlg(key.alg)) {
			throw new KeyActionRefused(
				409,
				'no key can be generated in this algorithm to replace it; promote another key in its algorithm first',
				{ reason: 'no_replacement' }
			);
		}
		// Generated before the audit entry, so the entry can name it; stored after.
		fresh = { jwk: await freshJwk(key.alg), alg: key.alg };
	}
	const replacement = standby?.kid ?? fresh?.jwk.kid;

	await owner.audit('revoke', kid, {
		revoked: kid,
		...(replacement ? { signing: replacement } : {}),
		...(fresh ? { generated: fresh.jwk.kid } : {})
	});
	const at = new Date(Date.now());
	/* The replacement first, as a promotion writes its signer first: the algorithm is never without one. */
	if (standby) {
		await store.setState(owner.id, standby.kid, 'signing', at);
	} else if (fresh) {
		await store.createIfAbsent(
			recordOf(owner, fresh.jwk, fresh.alg, 'signing', at)
		);
	}
	const revoked = await store.setState(owner.id, kid, 'revoked', at);
	await owner.invalidate();
	if (!revoked) throw new AdminError(404, 'no such key');
	return {
		kid,
		state: 'revoked' as const,
		...(replacement ? { replacement } : {}),
		replacementGenerated: fresh !== undefined
	};
}
