import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
import { treaty } from '@elysiajs/eden';
import { resolveAdmin } from 'lib/admin/auth/rbac.ts';
import { jwksRoutes } from 'lib/admin/jwks/routes.ts';
import {
	adminSessionStore,
	adminAuditStore,
	getUserStore,
	jwksStore
} from 'lib/adapters/index.ts';
import { JWKS_KEYS } from 'lib/configs/keys.ts';
import { keystore, publicJWKS } from 'lib/configs/keystore.ts';
import { generateJWKS } from 'lib/helpers/jwks.ts';
import { calculateKid } from 'lib/configs/verifyJWKs.ts';
import { ADMIN_BUCKET_ID, ADMIN_SESSION_COOKIE } from 'lib/admin/consts.ts';

const app = new Elysia().use(resolveAdmin).use(jwksRoutes);
const client = treaty(app);

const PRIVATE_FIELDS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth'];

interface KeyView {
	kid: string;
	kty: string;
	alg?: string;
	use?: string;
	status: string;
	[k: string]: unknown;
}
interface JwksState {
	keys: KeyView[];
	restartRequired: boolean;
	changedKeys: string[];
	supportedAlgorithms: string[];
}

async function sessionCookieFor(roles: string[]) {
	const user = await getUserStore(ADMIN_BUCKET_ID).create(
		`${roles.join('-')}-${Math.random()}@x.io`,
		'hash',
		roles
	);
	const s = await adminSessionStore.create({
		userId: user._id,
		bucketId: ADMIN_BUCKET_ID,
		tokens: {},
		ttlSeconds: 60,
		absoluteTtlSeconds: 3600
	});
	return { cookie: `${ADMIN_SESSION_COOKIE}=${s._id}`, userId: user._id };
}

function assertNoPrivateMaterial(keys: KeyView[]) {
	for (const key of keys) {
		for (const field of PRIVATE_FIELDS) {
			expect(key[field]).toBeUndefined();
		}
	}
}

// The server's live key material. Generation hot-applies keys into these, so tests must restore
// them between runs alongside the persisted store.
const BOOT_RUNNING = publicJWKS.keys.slice();

// The store is keyed by kid, so a key carrying none is not addressable and cannot be cleared here —
// it would survive into every later spec. The case is real (a key provisioned out of band), so a
// test that creates one has to remove it by the store key itself; this fails loudly rather than
// leaking, which is a bug this suite has had to diagnose twice.
async function clearStore() {
	for (const k of await jwksStore.getAll()) {
		if (!k.kid) {
			throw new Error(
				'key store holds a key with no kid; clear it by its store key'
			);
		}
		await jwksStore.delete(k.kid);
	}
}

// Restore both the persisted store and the live key material to the boot key set so desired ==
// running: all keys `active`, no drift.
async function resetStore() {
	await clearStore();
	for (const k of JWKS_KEYS) await jwksStore.set(k.kid, k);
	keystore.clear();
	for (const k of JWKS_KEYS) keystore.add(structuredClone(k));
	publicJWKS.keys.length = 0;
	publicJWKS.keys.push(...BOOT_RUNNING);
}

describe('admin JWKS API — view (US1)', () => {
	beforeEach(resetStore);

	it('rejects anonymous access', async () => {
		const res = await client.admin.api.jwks.get();
		expect(res.status).toBe(401);
	});

	it('forbids a project_admin', async () => {
		const { cookie } = await sessionCookieFor(['project_admin']);
		const res = await client.admin.api.jwks.get({ headers: { cookie } });
		expect(res.status).toBe(403);
	});

	it('lists the boot key as active with no private material and no drift', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.jwks.get({ headers: { cookie } });
		expect(res.status).toBe(200);
		const body = res.data as JwksState;
		expect(body.keys.length).toBe(JWKS_KEYS.length);
		expect(body.keys.every((k) => k.status === 'active')).toBe(true);
		expect(body.restartRequired).toBe(false);
		expect(body.changedKeys).toEqual([]);
		expect(body.supportedAlgorithms).toEqual(['RS256', 'RS384', 'RS512']);
		assertNoPrivateMaterial(body.keys);
	});

	// The view reads the persisted store directly, so it sees keys exactly as an operator wrote
	// them — a key provisioned out of band may carry only the members its schema requires. `use`
	// is inferred from `alg` (as verifyJWKs does at boot) rather than reported as absent, so the
	// admin view and /jwks agree about what the key is for.
	it('infers `use` for a store key provisioned without one', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const {
			keys: [key]
		} = await generateJWKS('RS256');
		const { use, ...withoutUse } = key;
		expect(use).toBe('sig'); // guard: the fixture really did carry a `use` to strip
		await jwksStore.set(key.kid, withoutUse);

		const res = await client.admin.api.jwks.get({ headers: { cookie } });
		const body = res.data as JwksState;
		const view = body.keys.find((k) => k.kid === key.kid);
		expect(view?.use).toBe('sig');
	});

	// A key provisioned without a `kid` is reported under the RFC 7638 thumbprint the server would
	// itself assign at boot. Every id in the response has to be that same derived kid: reporting
	// the raw (absent) one would put `undefined` in changedKeys and leave the entry uncorrelatable
	// with the key it describes.
	it('reports a store key provisioned without a kid under its derived kid', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const {
			keys: [key]
		} = await generateJWKS('RS256');
		const { kid, ...withoutKid } = key;
		await jwksStore.set(kid, withoutKid);

		// Removed by the store key, not in resetStore: that deletes by each key's own `kid`, which
		// this one does not have, so it would outlive the spec and leak into every later one.
		try {
			const res = await client.admin.api.jwks.get({ headers: { cookie } });
			const body = res.data as JwksState;

			// Not the store's map key — the thumbprint, which is what verifyJWKs would assign.
			const derived = calculateKid(withoutKid);
			expect(derived).not.toBe(kid);

			const view = body.keys.find((k) => k.kid === derived);
			expect(view).toBeDefined();
			// Not live until a restart normalizes it into the running set.
			expect(view?.status).toBe('pending activation');
			expect(body.changedKeys).toContain(derived);
			expect(body.changedKeys.every((k) => typeof k === 'string')).toBe(true);
			expect(body.keys.every((k) => typeof k.kid === 'string')).toBe(true);
		} finally {
			await jwksStore.delete(kid);
		}
	});
});

describe('admin JWKS API — generate (US2)', () => {
	beforeEach(resetStore);

	it('generates a signing key that is live immediately (active), audited, no private material', async () => {
		const { cookie, userId } = await sessionCookieFor(['super_admin']);
		const before = (await client.admin.api.jwks.get({ headers: { cookie } }))
			.data as JwksState;
		const beforeKids = new Set(before.keys.map((k) => k.kid));
		const res = await client.admin.api.jwks.post(
			{ alg: 'RS256' },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(200);
		const body = res.data as JwksState;
		expect(body.keys.length).toBe(before.keys.length + 1);
		const created = body.keys.find((k) => !beforeKids.has(k.kid));
		expect(created).toBeDefined();
		expect(created?.alg).toBe('RS256');
		// Hot-applied into the running provider: live at once, no restart required.
		expect(created?.status).toBe('active');
		expect(body.restartRequired).toBe(false);
		expect(body.changedKeys).not.toContain(created!.kid);
		assertNoPrivateMaterial(body.keys);
		// Served live at /jwks (present in the running published set).
		expect(publicJWKS.keys.some((k) => k.kid === created!.kid)).toBe(true);

		const { entries: audit } = await adminAuditStore.list({
			targetType: 'jwks',
			targetId: created!.kid
		});
		expect(audit.length).toBe(1);
		expect(audit[0].action).toBe('jwks.generate');
		expect(audit[0].actorId).toBe(userId);
		expect(audit[0].actorEmail).toBeTruthy();
	});

	it('rejects an unsupported algorithm with 422', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api.jwks.post(
			{ alg: 'ES256' },
			{ headers: { cookie } }
		);
		expect(res.status).toBe(422);
	});

	it('rejects anonymous and project_admin generation', async () => {
		const anon = await client.admin.api.jwks.post({ alg: 'RS256' });
		expect(anon.status).toBe(401);
		const { cookie } = await sessionCookieFor(['project_admin']);
		const forbidden = await client.admin.api.jwks.post(
			{ alg: 'RS256' },
			{ headers: { cookie } }
		);
		expect(forbidden.status).toBe(403);
	});
});

describe('admin JWKS API — retire (US3)', () => {
	beforeEach(resetStore);

	// Seed a second signing key directly via the store (independent of the generate endpoint)
	// so this story is testable on its own.
	async function seedSecondKey(): Promise<string> {
		const {
			keys: [key]
		} = await generateJWKS('RS256');
		const { kid } = key;
		await jwksStore.set(kid, key);
		return kid;
	}

	it('deletes a non-last key and records an audit entry', async () => {
		const { cookie, userId } = await sessionCookieFor(['super_admin']);
		const seededKid = await seedSecondKey();
		const res = await client.admin.api
			.jwks({ kid: seededKid })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);
		const body = res.data as JwksState;
		expect(body.keys.some((k) => k.kid === seededKid)).toBe(false);

		const { entries: audit } = await adminAuditStore.list({
			targetType: 'jwks',
			targetId: seededKid
		});
		expect(audit.length).toBe(1);
		expect(audit[0].action).toBe('jwks.delete');
		expect(audit[0].actorId).toBe(userId);
	});

	it('marks a deleted active (running) key as pending removal', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		await seedSecondKey(); // keep >=1 signing key after removing the boot key
		const bootKid = JWKS_KEYS[0].kid;
		const res = await client.admin.api
			.jwks({ kid: bootKid })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(200);
		const body = res.data as JwksState;
		const view = body.keys.find((k) => k.kid === bootKid);
		expect(view?.status).toBe('pending removal');
		expect(body.restartRequired).toBe(true);
		expect(body.changedKeys).toContain(bootKid);
	});

	it('refuses to remove the last signing key with 422', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		// Reduce the store to a single signing key so its removal would empty the set.
		await clearStore();
		const soleKid = JWKS_KEYS[0].kid;
		await jwksStore.set(soleKid, JWKS_KEYS[0]);
		const res = await client.admin.api
			.jwks({ kid: soleKid })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(422);
	});

	it('returns 404 for an unknown kid', async () => {
		const { cookie } = await sessionCookieFor(['super_admin']);
		const res = await client.admin.api
			.jwks({ kid: 'does-not-exist' })
			.delete(undefined, { headers: { cookie } });
		expect(res.status).toBe(404);
	});

	it('rejects anonymous and project_admin deletion', async () => {
		const seededKid = await seedSecondKey();
		const anon = await client.admin.api.jwks({ kid: seededKid }).delete();
		expect(anon.status).toBe(401);
		const { cookie } = await sessionCookieFor(['project_admin']);
		const forbidden = await client.admin.api
			.jwks({ kid: seededKid })
			.delete(undefined, { headers: { cookie } });
		expect(forbidden.status).toBe(403);
	});
});
