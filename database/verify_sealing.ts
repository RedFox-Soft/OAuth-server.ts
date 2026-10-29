import { generateKeyPairSync, randomBytes } from 'node:crypto';

import type { SealKind, SealTarget } from '../lib/consts/sealed_fields.js';
import type {
	BucketKeysStoreInstance,
	KeyringStateStoreInstance,
	ModelAdapter,
	SealingStoreInstance,
	SecretStoreInstance,
	SmtpSettingsStoreInstance,
	UserBucketStoreInstance,
	UserStoreInstance
} from '../lib/adapters/types.js';

type Check = (name: string, ok: boolean, detail?: string) => void;

type Singleton = 'dpopNonceSecret' | 'errorOriginSalt';

/*
 * The stores the checks seed through and read back from: the undecorated ones of the backend under test, so
 * what is seeded is what is stored and what is read back is the leaf the pass wrote. `forget` removes a
 * `serviceConfig` document this run created, which no store contract can do.
 */
export interface SealingFixture {
	sealing: SealingStoreInstance;
	keyring: () => KeyringStateStoreInstance;
	buckets: UserBucketStoreInstance;
	users: (bucketId: string) => UserStoreInstance;
	keys: BucketKeysStoreInstance;
	smtp: SmtpSettingsStoreInstance;
	secret: (name: Singleton) => SecretStoreInstance;
	model: (
		name: 'Client' | 'TotpEnrollment'
	) => ModelAdapter<Record<string, unknown>>;
	forget: (documentName: string) => Promise<void>;
}

function same(a: unknown, b: string | Uint8Array): boolean {
	if (typeof a === 'string' || typeof b === 'string') return a === b;
	return a instanceof Uint8Array && Buffer.from(a).equals(Buffer.from(b));
}

function shown(value: unknown): string {
	if (value instanceof Uint8Array) return `bytes(${value.length})`;
	if (value === undefined) return 'undefined';
	return JSON.stringify(value);
}

function rsaKey(kid: string) {
	const { n, e, d, p, q, dp, dq, qi } = generateKeyPairSync('rsa', {
		modulusLength: 2048
	}).privateKey.export({ format: 'jwk' });
	if (!n || !e || !d || !p || !q || !dp || !dq || !qi) {
		throw new Error('the generated RSA key has no private members');
	}
	return {
		kty: 'RSA' as const,
		alg: 'RS256' as const,
		kid,
		n,
		e,
		d,
		p,
		q,
		dp,
		dq,
		qi
	};
}

/*
 * The encryption pass's store (specs/116 R8) against a real datastore. What an in-memory double cannot show
 * is whether a compare-and-set reaches exactly the stored leaf it names — the second of three providers that
 * all hold the same value, the SMTP password where the settings document nests it, the bytes of a singleton
 * secret after a round trip through BSON or bytea — and whether a stale observed value writes nothing. Shared
 * by verify_mongodb.ts and verify_postgres.ts so both backends answer the same questions in the same words.
 */
export async function verifySealing(
	fixture: SealingFixture,
	check: Check
): Promise<void> {
	const { sealing } = fixture;
	const stamp = `${Date.now()}-${randomBytes(3).toString('hex')}`;

	/*
	 * Finds the seeded leaf, seals it, then seals it again from the value the first write replaced: the second
	 * is the pass meeting an edit made between its read and its write, and must change nothing.
	 */
	async function compareAndSet(
		label: string,
		kind: SealKind,
		matches: (target: SealTarget) => boolean,
		seeded: string | Uint8Array,
		readBack: () => Promise<unknown>,
		next: string | Uint8Array,
		late: string | Uint8Array
	): Promise<void> {
		const leaf = (await sealing.scan(kind)).find((found) =>
			matches(found.target)
		);
		check(
			`${label}: the scan finds the leaf as it is stored`,
			leaf !== undefined && same(leaf.value, seeded),
			shown(leaf?.value)
		);
		if (!leaf) return;
		const wrote = await sealing.sealAt(leaf.target, leaf.value, next);
		const afterWrite = await readBack();
		check(
			`${label}: a compare-and-set from the stored value writes it`,
			wrote && same(afterWrite, next),
			`${wrote} ${shown(afterWrite)}`
		);
		const wroteStale = await sealing.sealAt(leaf.target, leaf.value, late);
		const afterStale = await readBack();
		check(
			`${label}: a compare-and-set from a stale value writes nothing`,
			!wroteStale && same(afterStale, next),
			`${wroteStale} ${shown(afterStale)}`
		);
	}

	/* ---- a bucket of three providers holding one value, a person enrolled, a pending enrolment ---- */

	const shared = {
		secret: `shared-secret-${stamp}`,
		key: `shared-key-${stamp}`
	};
	const provider = (id: string) => ({
		id,
		displayName: id,
		enabled: true,
		issuer: `https://${id}.invalid`,
		clientId: `${id}-client`,
		clientSecret: shared.secret,
		signingKey: shared.key,
		scopes: ['openid', 'email'],
		emailTrusted: false,
		provisioning: 'jit' as const,
		allowedEmailDomains: [],
		emailClaim: 'email'
	});
	const bucket = await fixture.buckets.create({
		name: `sealing-${stamp}`,
		ownerGroupId: 'unassigned',
		federation: [provider('first'), provider('middle'), provider('last')]
	});
	const users = fixture.users(bucket._id);
	const enrolled = await users.create(`enrolled-${stamp}@x.io`, 'unused', true);
	const totpSecret = `TOTPSECRET${stamp.replace(/[^0-9]/g, '')}`;
	await users.update(enrolled._id, {
		totp: { secret: totpSecret, enrolledAt: new Date(), lastStep: 0 }
	});
	const unenrolled = await users.create(
		`unenrolled-${stamp}@x.io`,
		'unused',
		true
	);

	const clientId = `sealing-client-${stamp}`;
	const clientSecret = `client-secret-${stamp}`;
	await fixture.model('Client').upsert(clientId, {
		clientId,
		clientSecret,
		redirectUris: ['https://rp.invalid/cb']
	});

	const enrolmentId = `sealing-enrolment-${stamp}`;
	const pendingSecret = `PENDING${stamp.replace(/[^0-9]/g, '')}`;
	await fixture.model('TotpEnrollment').upsert(
		enrolmentId,
		{
			accountId: enrolled._id,
			bucketId: bucket._id,
			secret: pendingSecret,
			exp: Math.floor(Date.now() / 1000) + 600
		},
		600
	);

	const kid = `sealing-${stamp}`;
	const jwk = rsaKey(kid);
	await fixture.keys.createIfAbsent({
		_id: `${bucket._id} #sealing`,
		bucketId: bucket._id,
		kid,
		jwk,
		alg: 'RS256',
		use: 'sig',
		state: 'signing',
		createdAt: new Date(),
		stateChangedAt: new Date()
	});

	const smtpBefore = await fixture.smtp.get();
	const smtpPassword = `smtp-password-${stamp}`;
	await fixture.smtp.set({
		host: 'smtp.invalid',
		port: 587,
		secure: false,
		username: 'sealing',
		password: smtpPassword,
		fromName: 'Sealing',
		fromEmail: 'sealing@x.io'
	});

	const singletonsBefore = new Map<Singleton, unknown>();
	for (const name of ['dpopNonceSecret', 'errorOriginSalt'] as const) {
		const before = await fixture.secret(name).read();
		singletonsBefore.set(name, before);
		if (!(before instanceof Uint8Array)) {
			await fixture.secret(name).create(randomBytes(32));
		}
	}

	const keyringBefore = await fixture.keyring().read();

	try {
		/* ---- the providers: the middle one of three equal values, and only it ---- */

		for (const [kind, field, seeded] of [
			['providerSecret', 'clientSecret', shared.secret],
			['providerSigningKey', 'signingKey', shared.key]
		] as const) {
			const federation = async () =>
				(await fixture.buckets.find(bucket._id))?.federation ?? [];
			await compareAndSet(
				kind,
				kind,
				(target) =>
					target.kind === kind &&
					target.bucketId === bucket._id &&
					target.providerId === 'middle',
				seeded,
				async () => (await federation())[1]?.[field],
				`sealed-${kind}-${stamp}`,
				`late-${kind}-${stamp}`
			);
			const after = await federation();
			check(
				`${kind}: the provider in the middle is the one changed, its neighbours keep their value`,
				after.map((p) => p.id).join() === 'first,middle,last' &&
					after[0]?.[field] === seeded &&
					after[2]?.[field] === seeded,
				shown(after.map((p) => p[field]))
			);
		}

		/* ---- an application's secret, a pending enrolment ---- */

		await compareAndSet(
			'clientSecret',
			'clientSecret',
			(target) =>
				target.kind === 'clientSecret' && target.clientId === clientId,
			clientSecret,
			async () => (await fixture.model('Client').find(clientId))?.clientSecret,
			`sealed-client-${stamp}`,
			`late-client-${stamp}`
		);

		await compareAndSet(
			'totpPending',
			'totpPending',
			(target) =>
				target.kind === 'totpPending' &&
				target.uid === enrolmentId &&
				target.bucketId === bucket._id &&
				target.accountId === enrolled._id,
			pendingSecret,
			async () =>
				(await fixture.model('TotpEnrollment').find(enrolmentId))?.secret,
			`sealed-pending-${stamp}`,
			`late-pending-${stamp}`
		);

		/* ---- the SMTP password, read back through the settings store, which reads the nested leaf ---- */

		await compareAndSet(
			'smtpPassword (where the settings store reads it)',
			'smtpPassword',
			(target) => target.kind === 'smtpPassword',
			smtpPassword,
			async () => (await fixture.smtp.get())?.password,
			`sealed-smtp-${stamp}`,
			`late-smtp-${stamp}`
		);
		const smtp = await fixture.smtp.get();
		check(
			'smtpPassword: the rest of the settings are untouched',
			smtp?.host === 'smtp.invalid' && smtp.username === 'sealing',
			shown(smtp?.host)
		);

		/* ---- a private key member, and a revoked key read as revoked ---- */

		const keyLeaves = (await sealing.scan('privateKey')).filter(
			(leaf) => leaf.target.kind === 'privateKey' && leaf.target.kid === kid
		);
		check(
			'privateKey: the scan finds all six private members, not revoked',
			keyLeaves.length === 6 && keyLeaves.every((leaf) => !leaf.revoked),
			shown(keyLeaves.map((leaf) => leaf.target))
		);
		await compareAndSet(
			'privateKey',
			'privateKey',
			(target) =>
				target.kind === 'privateKey' &&
				target.kid === kid &&
				target.bucketId === bucket._id &&
				target.member === 'd',
			jwk.d,
			async () => {
				const stored = (await fixture.keys.find(bucket._id, kid))?.jwk;
				return stored && 'd' in stored ? stored.d : undefined;
			},
			`sealed-d-${stamp}`,
			`late-d-${stamp}`
		);
		const keyAfter = (await fixture.keys.find(bucket._id, kid))?.jwk;
		check(
			"privateKey: the key's other members and its public half are untouched",
			keyAfter !== undefined &&
				'p' in keyAfter &&
				keyAfter.p === jwk.p &&
				'n' in keyAfter &&
				keyAfter.n === jwk.n,
			''
		);
		await fixture.keys.setState(bucket._id, kid, 'revoked', new Date());
		const revokedLeaves = (await sealing.scan('privateKey')).filter(
			(leaf) => leaf.target.kind === 'privateKey' && leaf.target.kid === kid
		);
		check(
			'privateKey: a revoked key is scanned as revoked',
			revokedLeaves.length === 6 && revokedLeaves.every((leaf) => leaf.revoked),
			shown(revokedLeaves.map((leaf) => leaf.revoked))
		);

		/* ---- a person's authenticator, in the bucket's own user area ---- */

		const totpLeaves = (await sealing.scan('totpSecret')).filter(
			(leaf) =>
				leaf.target.kind === 'totpSecret' && leaf.target.bucketId === bucket._id
		);
		check(
			'totpSecret: only the enrolled person is scanned',
			totpLeaves.length === 1 &&
				totpLeaves[0]?.target.kind === 'totpSecret' &&
				totpLeaves[0].target.userId === enrolled._id &&
				!totpLeaves.some(
					(leaf) =>
						leaf.target.kind === 'totpSecret' &&
						leaf.target.userId === unenrolled._id
				),
			shown(totpLeaves.map((leaf) => leaf.target))
		);
		await compareAndSet(
			'totpSecret',
			'totpSecret',
			(target) =>
				target.kind === 'totpSecret' &&
				target.bucketId === bucket._id &&
				target.userId === enrolled._id,
			totpSecret,
			async () => (await users.find(enrolled._id))?.totp?.secret,
			`sealed-totp-${stamp}`,
			`late-totp-${stamp}`
		);
		const enrolledAfter = await users.find(enrolled._id);
		check(
			'totpSecret: the enrolment keeps its other fields',
			enrolledAfter?.totp?.lastStep === 0 &&
				enrolledAfter.totp.enrolledAt instanceof Date,
			shown(enrolledAfter?.totp?.lastStep)
		);

		/* ---- the two singleton secrets, as bytes ---- */

		for (const name of ['dpopNonceSecret', 'errorOriginSalt'] as const) {
			const stored = await fixture.secret(name).read();
			if (!(stored instanceof Uint8Array)) {
				check(`${name}: the seeded secret reads back as bytes`, false);
				continue;
			}
			const leaf = (await sealing.scan(name)).at(0);
			check(
				`${name}: the scan's value is bytes a caller's guard accepts`,
				leaf?.value instanceof Uint8Array,
				shown(leaf?.value)
			);
			const next = randomBytes(48);
			await compareAndSet(
				name,
				name,
				(target) => target.kind === name,
				stored,
				() => fixture.secret(name).read(),
				next,
				randomBytes(48)
			);
			const roundTrip = await fixture.secret(name).read();
			check(
				`${name}: the sealed bytes round-trip as a Uint8Array`,
				roundTrip instanceof Uint8Array && same(roundTrip, next),
				shown(roundTrip)
			);
		}

		/* ---- the keyring state ---- */

		const keyring = fixture.keyring();
		const day = new Date().toISOString().slice(0, 10).replace(/-/g, '');
		const keyId = `${day}-${randomBytes(3).toString('base64url').slice(0, 4)}`;
		const first = await keyring.addFingerprintIfAbsent(keyId, `first-${stamp}`);
		const second = await fixture
			.keyring()
			.addFingerprintIfAbsent(keyId, `second-${stamp}`);
		check(
			'keyring: a second fingerprint for a recorded key id gets the first one back',
			first === `first-${stamp}` && second === first,
			shown([first, second])
		);
		const racedId = `${day}-${randomBytes(3).toString('base64url').slice(0, 4)}`;
		const raced = await Promise.all(
			['a', 'b', 'c', 'd'].map((suffix) =>
				fixture.keyring().addFingerprintIfAbsent(racedId, `${suffix}-${stamp}`)
			)
		);
		check(
			'keyring: four processes recording one key id at once agree on one fingerprint',
			new Set(raced).size === 1,
			shown(raced)
		);
		const confirmed = { at: new Date().toISOString(), by: `sealing-${stamp}` };
		await keyring.patch({
			setupToken: `token-${stamp}`,
			backupConfirmed: confirmed
		});
		const patched = await keyring.read();
		check(
			'keyring: patched fields read back',
			patched?.setupToken === `token-${stamp}` &&
				patched.backupConfirmed?.by === confirmed.by &&
				patched.fingerprints[keyId] === first,
			shown(patched)
		);
		await keyring.patch({ setupToken: null });
		const unset = await keyring.read();
		check(
			'keyring: a null removes a field and leaves the others',
			unset !== null &&
				!('setupToken' in unset) &&
				unset.backupConfirmed?.by === confirmed.by &&
				unset.fingerprints[keyId] === first,
			shown(unset)
		);
	} finally {
		await fixture.model('Client').destroy(clientId);
		await fixture.model('TotpEnrollment').destroy(enrolmentId);
		await fixture.keys.destroyByBucket(bucket._id);
		await users.destroy(enrolled._id);
		await users.destroy(unenrolled._id);
		await users.destroyArea();
		await fixture.buckets.destroy(bucket._id);

		if (smtpBefore) await fixture.smtp.set(smtpBefore);
		else await fixture.forget('smtpSettings');

		for (const [name, before] of singletonsBefore) {
			if (before instanceof Uint8Array) {
				await fixture
					.secret(name)
					.replace(await fixture.secret(name).read(), Buffer.from(before));
			} else if (before === null || before === undefined) {
				await fixture.forget(name);
			}
		}

		/*
		 * The fingerprints this run recorded cannot be removed through the store, so a keyring state that was
		 * here before the run gets its patched fields back and keeps those two ids, which name no key.
		 */
		if (keyringBefore === null) {
			await fixture.forget('keyringState');
		} else {
			await fixture.keyring().patch({
				setupToken: keyringBefore.setupToken ?? null,
				backupConfirmed: keyringBefore.backupConfirmed ?? null
			});
		}
	}
}
