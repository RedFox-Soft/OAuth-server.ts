import { describe, it, expect, beforeEach, mock } from 'bun:test';
import { BSON, Binary, ObjectId } from 'mongodb';
import { Type } from '@sinclair/typebox';

import { present, shaped } from 'test/shape.js';

/*
 * The tier `wiki/concepts/mongodb-test-fidelity.md` described and nobody built. Recorded as G-008.
 *
 * Removing the unwrap in `lib/adapters/mongodb/singletonSecretStore.ts` used to leave this directory
 * at 294 pass / 0 fail and the whole suite green, because every other store spec here exercises the
 * MEMORY implementation — the sibling files say so in as many words, and their reason is real:
 * `lib/adapters/mongodb/db.ts` awaits `connect()` at module scope and throws without MONGODB_URI, so
 * the MongoDB class cannot simply be imported.
 *
 * What those files concluded from that — "the MongoDB class is verified by hand" — is one step short.
 * `db.js` is the only thing standing in the way and nothing else in this suite imports it, so
 * substituting that one module lets the REAL class run here: the real `read`, the real `create`, the
 * real unwrap. The collection underneath serialises through BSON on write and deserialises on read,
 * which is the entire mechanism the defect turned on. A Buffer goes in; BSON has no Buffer, so a
 * `Binary` comes back; left wrapped it is the exact shape the callers' predicates reject, and the
 * server cannot boot or recover by restarting.
 *
 * Re-implementing the unwrap in this file instead would have been worthless in a way that is easy to
 * miss: the historical defect would still pass. The test has to run the product's own code for the
 * mutation to mean anything.
 *
 * No server and no new dependency — `bson` arrives with `mongodb`, which is already a dependency.
 */

const documents = new Map<string, Record<string, unknown>>();

/*
 * What the driver does to a document on the way to disk and back. The whole point of the file. The
 * options are the write's own: `ignoreUndefined` is what decides whether an undefined member reaches
 * the disk as null. The default is the *driver's*, not bson's: bare `BSON.serialize` drops an undefined
 * member, while the driver passes `ignoreUndefined: false` unless the write says otherwise
 * (node_modules/mongodb/lib/bson.js), so taking bson's default here would store as absent exactly
 * what a real deployment stores as null.
 */
function throughBSON(
	doc: Record<string, unknown>,
	options?: { ignoreUndefined?: boolean }
): Record<string, unknown> {
	return BSON.deserialize(
		BSON.serialize(doc, {
			ignoreUndefined: options?.ignoreUndefined ?? false
		})
	);
}

// The secret stores key by a derived ObjectId, the others by a string id.
const keyOf = (id: unknown): string =>
	id instanceof ObjectId ? id.toHexString() : String(id);

function duplicateKey(): Error & { code: number } {
	return Object.assign(new Error('E11000 duplicate key'), { code: 11000 });
}

await mock.module('lib/adapters/mongodb/db.js', () => ({
	db: {
		/* Creating a bucket provisions its user area; that the area exists is all this file needs. */
		listCollections: () => ({ hasNext: async () => true }),
		createCollection: async () => {},
		collection: () => ({
			createIndex: async () => 'index',
			async findOne(filter: { _id: unknown }) {
				return documents.get(keyOf(filter._id)) ?? null;
			},
			async insertOne(
				doc: { _id: unknown } & Record<string, unknown>,
				options?: { ignoreUndefined?: boolean }
			) {
				const key = keyOf(doc._id);
				if (documents.has(key)) throw duplicateKey();
				documents.set(key, throughBSON(doc, options));
				return { acknowledged: true };
			},
			async updateOne(
				filter: { _id: unknown },
				update: { $set: Record<string, unknown> },
				options?: { upsert?: boolean; ignoreUndefined?: boolean }
			) {
				const key = keyOf(filter._id);
				const current = documents.get(key);
				if (!current && !options?.upsert) return { matchedCount: 0 };
				documents.set(
					key,
					throughBSON({ _id: filter._id, ...current, ...update.$set }, options)
				);
				return { matchedCount: current ? 1 : 0 };
			}
		})
	},
	ping: async () => {}
}));

const { SingletonSecretStore } =
	await import('lib/adapters/mongodb/singletonSecretStore.js');
const { AdminSessionStore } =
	await import('lib/adapters/mongodb/adminSessionStore.js');
const { UserBucketStore } =
	await import('lib/adapters/mongodb/userBucketStore.js');
const { MongoAdapter } = await import('lib/adapters/mongodb/mongoAdapter.js');
const { Session } = await import('lib/models/session.js');

/* The store derives its _id from the document name, so seeding a case directly uses the same rule. */
function idFor(documentName: string): string {
	return new Bun.CryptoHasher('sha256')
		.update(documentName)
		.digest('hex')
		.substring(0, 24);
}

function seed(documentName: string, secret: unknown): void {
	documents.set(
		idFor(documentName),
		throughBSON({
			_id: new ObjectId(idFor(documentName)),
			secret,
			updatedAt: new Date()
		})
	);
}

const bytes = (fill: number): Buffer => Buffer.alloc(32, fill);

/**
 * @proves A singleton secret survives MongoDB's own storage encoding as the bytes that were written,
 * and a stored value the encoding did not produce is handed to the caller rather than coerced.
 */
describe('a singleton secret in MongoDB storage', () => {
	beforeEach(() => documents.clear());

	it('returns the bytes that were written, for the nonce secret', async () => {
		const store = new SingletonSecretStore('dpopNonceSecret');
		const secret = bytes(0x11);

		const created = await store.create(secret);

		expect(created).toBeInstanceOf(Uint8Array);
		expect(Buffer.from(shaped(Type.Uint8Array(), created)).equals(secret)).toBe(
			true
		);
		expect(
			Buffer.from(shaped(Type.Uint8Array(), await store.read())).equals(secret)
		).toBe(true);
	});

	/*
	 * The salt separately, not because the code differs — one class serves both — but because its
	 * failure mode is the worse of the two: a salt that changes identity changes every pairwise
	 * subject the deployment has ever issued.
	 */
	it('returns the bytes that were written, for the pairwise salt', async () => {
		const store = new SingletonSecretStore('pairwiseSalt');
		const salt = bytes(0x22);

		const created = await store.create(salt);

		expect(created).toBeInstanceOf(Uint8Array);
		expect(Buffer.from(shaped(Type.Uint8Array(), created)).equals(salt)).toBe(
			true
		);
		expect(
			Buffer.from(shaped(Type.Uint8Array(), await store.read())).equals(salt)
		).toBe(true);
	});

	/*
	 * Subtype 0x80 is the user-defined range. The store's comment commits to unwrapping ANY subtype
	 * rather than only the default one it writes, on the grounds that the caller's length check is
	 * what judges the material — so a value some other writer stored under a different subtype must
	 * still arrive as bytes.
	 */
	it('returns usable material when the stored value carries a non-default binary subtype', async () => {
		const secret = bytes(0x33);
		seed('dpopNonceSecret', new Binary(secret, 0x80));

		const read = await new SingletonSecretStore('dpopNonceSecret').read();

		expect(read).toBeInstanceOf(Uint8Array);
		expect(Buffer.from(shaped(Type.Uint8Array(), read)).equals(secret)).toBe(
			true
		);
	});

	/*
	 * The other half of the same commitment, and the reason the unwrap is a conditional rather than an
	 * unconditional coercion: a value that is not binary at all is the caller's to refuse. Coercing it
	 * would make an unusable secret merely look usable, which is the failure this whole file exists
	 * to keep out of a deployment.
	 */
	it('passes a stored value through unchanged when it is not binary', async () => {
		seed('pairwiseSalt', 'not-a-secret');

		expect(await new SingletonSecretStore('pairwiseSalt').read()).toBe(
			'not-a-secret'
		);
	});

	it('reads nothing when the secret has never been provisioned', async () => {
		expect(await new SingletonSecretStore('pairwiseSalt').read()).toBeNull();
	});
});

/**
 * @proves A member a MongoDB writer leaves undefined is stored as absent, not as the BSON null the
 * driver writes by default — so the stored document has the shape its type declares, and nothing reads
 * a null where its writer meant nothing.
 */
describe('an optional member left undefined in MongoDB storage', () => {
	beforeEach(() => documents.clear());

	/* Every console session: the admin client has no refresh-token grant, so the token is undefined. */
	it('stores an admin session with no refresh token without one', async () => {
		const session = await new AdminSessionStore().create({
			userId: 'u-1',
			bucketId: 'b-1',
			activeGroupId: 'g-1',
			tokens: { accessToken: 'a', idToken: 'i', refreshToken: undefined },
			ttlSeconds: 60,
			absoluteTtlSeconds: 600
		});

		const stored = shaped(
			Type.Object({ tokens: Type.Record(Type.String(), Type.Unknown()) }),
			documents.get(session._id)
		);
		expect(Object.keys(stored.tokens).sort()).toEqual([
			'accessToken',
			'idToken'
		]);
	});

	/*
	 * A model record, through the model adapter every protocol record is written by. A sign-out that
	 * names no client — no id_token_hint, so no client, no post_logout_redirect_uri — leaves those
	 * members of the session's pending logout undefined. Stored as nulls, the session no longer matched
	 * its schema and was read as no session at all: the confirmation answered "could not find logout
	 * details", and the sign-in it was meant to end had silently gone with it.
	 */
	it('reads back a session holding a sign-out that names no client', async () => {
		const adapter = new MongoAdapter('Session');
		await adapter.upsert(
			'session-1',
			{
				kind: 'Session',
				jti: 'session-1',
				uid: 'uid-1',
				accountId: 'account-1',
				exp: Math.floor(Date.now() / 1000) + 600,
				state: {
					secret: 'xsrf',
					clientId: undefined,
					state: undefined,
					postLogoutRedirectUri: undefined
				}
			},
			600
		);

		const stored = present(await adapter.find('session-1'), 'stored session');
		const session = present(await Session.fromStored(stored), 'session');
		expect(session.payload.state?.secret).toBe('xsrf');
	});

	/* A bucket addressed by its host carries no slug. */
	it('stores a bucket created without a slug without one', async () => {
		const bucket = await new UserBucketStore().create({
			name: 'hosted',
			ownerGroupId: 'unassigned',
			host: 'hosted.example.test'
		});

		expect(documents.get(bucket._id)).not.toHaveProperty('slug');
	});
});
