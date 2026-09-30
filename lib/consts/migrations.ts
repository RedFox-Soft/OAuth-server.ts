/*
 * The ordered set of schema migrations.
 *
 * Import-free, for the reason `storage_inventory.ts` is: a drift guard has to read it without a
 * datastore, and anything reaching an adapter would make that impossible.
 *
 * The one migration this server had before these — `managedBy` to `ownerGroupId` — is retired rather
 * than carried forward: preserving it would have meant porting a one-off data rewrite to a backend
 * whose deployments cannot contain the shape it looks for, and would teach every future author that
 * historical entries belong here.
 *
 * The runner takes the set as an argument instead of importing it. That is what lets a fixture set
 * cover the machinery — the same shape `validateConfiguration` uses to check a candidate configuration
 * with the production rules.
 *
 * The only imports are other import-free declarations, which keeps the drift guard able to read this
 * without a datastore.
 */

import { STORE_AREAS } from './storage_inventory.js';
import { isServedAtTheRoot } from '../admin/consts.js';
import { declarationId, ROOT_NAMESPACE } from '../resources/declaration_id.js';
import { ROOT_KEY_OWNER } from './key_owner.js';

/*
 * One backend's half of a migration.
 *
 * `apply` takes the handle as `unknown` and narrows it internally. Typing it per backend would mean
 * importing a driver type here, which would cost this module its import-freedom; one documented
 * assertion inside a step is the cheaper trade, and there is exactly one such assertion per migration
 * per backend.
 */
export interface MigrationStep {
	readonly apply: (handle: unknown) => Promise<void>;
}

/*
 * A migration one backend does not need.
 *
 * The reason is required, and "not needed here" is not one — say why the other backend needs it and
 * this one does not. The same rule the inventory applies to `reason` on an unowned area and to
 * `reaped: null`: an absence has to be a decision somebody wrote down.
 */
export interface MigrationNoop {
	readonly noop: true;
	readonly reason: string;
}

export interface Migration {
	/* Stable, ordered, never reused. The array's order is the application order; nothing infers it. */
	readonly id: string;
	readonly description: string;
	/*
	 * Whether the change can be undone. `false` is surfaced to the operator before the migration runs,
	 * so "restore a backup" is a decision made in advance rather than discovered afterwards.
	 */
	readonly reversible: boolean;
	/*
	 * HOW this step is safe to apply twice — a sentence, not a boolean, because the useful content is
	 * the argument and a boolean would just be ticked.
	 *
	 * Required of every migration, on both backends. A standalone `mongod` is a supported topology and
	 * has no multi-document transaction, so a crash between a migration's effect and its record leaves
	 * the effect applied and unrecorded, and the next run applies it again. A step that assumed it ran
	 * once would corrupt data at that point.
	 */
	readonly rerunnable: string;
	readonly mongodb: MigrationStep | MigrationNoop;
	readonly postgres: MigrationStep | MigrationNoop;
}

export function isNoop(
	half: MigrationStep | MigrationNoop
): half is MigrationNoop {
	return 'noop' in half;
}

/*
 * The namespace a legacy declaration belongs to, derived exactly as `namespaceOf` derives it at
 * runtime: a bucket with an address that is not served at the root is its own namespace, and anything
 * else — no project, no bucket, a bucket with no address, a reserved bucket — is the root. Restated
 * here rather than imported because `namespaceOf` reaches the adapters, which this module may not.
 */
function namespaceFor(
	bucket: Record<string, unknown> | null | undefined
): string {
	if (!bucket || typeof bucket._id !== 'string') return ROOT_NAMESPACE;
	const addressed = Boolean(bucket.slug || bucket.host);
	return addressed && !isServedAtTheRoot(bucket._id)
		? bucket._id
		: ROOT_NAMESPACE;
}

type Doc = Record<string, unknown>;

/* The part of the MongoDB driver's `Db` the step uses — declared structurally so this module imports no
 * driver. */
interface MongoHandle {
	collection(name: string): {
		find(filter: Doc): { toArray(): Promise<Doc[]> };
		findOne(filter: Doc): Promise<Doc | null>;
		updateOne(filter: Doc, update: Doc, options: Doc): Promise<unknown>;
		deleteOne(filter: Doc): Promise<unknown>;
	};
}

/* The part of Bun's SQL client the step uses: the tagged template, and the call form that quotes an
 * identifier. */
interface PostgresHandle {
	(strings: TemplateStringsArray, ...values: unknown[]): Promise<Doc[]>;
	(identifier: string): unknown;
}

const namespacedProtectedResources: Migration = {
	id: '2026-09-29-protected-resources-namespaced',
	description:
		'Key declared protected resources by namespace and identifier instead of by identifier alone',
	reversible: false,
	rerunnable:
		'Only records without a `namespace` field are touched. The namespaced copy is written with an insert that does nothing when the key is already present, and the legacy record is deleted after it, so a run interrupted between the two re-writes nothing and finishes the delete.',
	mongodb: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for MongoDB that is the driver's `Db`.
			const db = handle as MongoHandle;
			const resources = db.collection(STORE_AREAS.protectedResources);
			const legacy = await resources
				.find({ namespace: { $exists: false } })
				.toArray();
			for (const record of legacy) {
				const identifier = String(record._id);
				const project = await db
					.collection(STORE_AREAS.projects)
					.findOne({ _id: record.projectId });
				const bucket =
					typeof project?.bucketId === 'string'
						? await db
								.collection(STORE_AREAS.userBuckets)
								.findOne({ _id: project.bucketId })
						: null;
				const namespace = namespaceFor(bucket);
				const { _id: _legacyId, ...rest } = record;
				await resources.updateOne(
					{ _id: declarationId(namespace, identifier) },
					{ $setOnInsert: { ...rest, namespace, identifier } },
					{ upsert: true }
				);
				await resources.deleteOne({ _id: record._id });
			}
		}
	},
	postgres: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for PostgreSQL that is Bun's SQL client.
			const sql = handle as PostgresHandle;
			const area = sql(STORE_AREAS.protectedResources);
			const legacy = await sql`
				SELECT id, doc FROM ${area} WHERE NOT (doc ? 'namespace')
			`;
			for (const row of legacy) {
				const identifier = String(row.id);
				const doc = row.doc as Doc;
				const [project] = await sql`
					SELECT doc FROM ${sql(STORE_AREAS.projects)} WHERE id = ${String(doc.projectId)}
				`;
				const bucketId = (project?.doc as Doc | undefined)?.bucketId;
				const [bucket] =
					typeof bucketId === 'string'
						? await sql`
								SELECT doc FROM ${sql(STORE_AREAS.userBuckets)} WHERE id = ${bucketId}
							`
						: [];
				const namespace = namespaceFor(bucket?.doc as Doc | undefined);
				const _id = declarationId(namespace, identifier);
				await sql`
					INSERT INTO ${area} (id, doc, expires_at)
					VALUES (${_id}, ${{ ...doc, _id, namespace, identifier }}, NULL)
					ON CONFLICT (id) DO NOTHING
				`;
				await sql`DELETE FROM ${area} WHERE id = ${identifier}`;
			}
		}
	}
};

/*
 * Where the root issuer's keys lived before they took the lifecycle every issuer's keys follow: flat JWKs
 * keyed by `kid`, with no state. Named here, by its literal, because the area is gone from the inventory
 * — this migration and the provisioning scripts' "anything left to migrate?" check are its only readers.
 */
export const LEGACY_ROOT_KEYS_AREA = 'jwks';

/*
 * Which legacy keys become `signing`: per algorithm, the key the server was signing with — the first
 * signing key of that algorithm in the order the store returned (key selection took the first match),
 * or, where the store has no order, the lowest kid in byte order, a rule the operator can read and then
 * override with a promotion. An algorithm that already has a migrated signer — a run interrupted part-way
 * — gets no second one. Encryption keys never sign.
 */
export function rootSignersOf(
	keys: readonly { kid: string; alg: string; use?: string }[],
	{
		ordered,
		alreadySigning = []
	}: { ordered: boolean; alreadySigning?: readonly string[] }
): Set<string> {
	const candidates = keys.filter((key) => key.use !== 'enc');
	const inOrder = ordered
		? candidates
		: [...candidates].sort((a, b) =>
				a.kid < b.kid ? -1 : a.kid > b.kid ? 1 : 0
			);
	const taken = new Set(alreadySigning);
	const signers = new Set<string>();
	for (const key of inOrder) {
		if (taken.has(key.alg)) continue;
		taken.add(key.alg);
		signers.add(key.kid);
	}
	return signers;
}

/* A legacy flat JWK as the new record, or the reason it cannot be one. */
function rootKeyRecord(jwk: Doc, signing: boolean, at: Date): Doc {
	const { _id: _legacyId, updatedAt: _updatedAt, ...material } = jwk;
	if (typeof material.kid !== 'string' || typeof material.alg !== 'string') {
		throw new Error(
			'a stored root key has no kid or no alg; give it both before migrating, as every key the server generates has'
		);
	}
	const use = material.use === 'enc' ? 'enc' : 'sig';
	return {
		_id: `${ROOT_KEY_OWNER} ${material.kid}`,
		bucketId: ROOT_KEY_OWNER,
		kid: material.kid,
		jwk: { ...material, use },
		alg: material.alg,
		use,
		state: signing && use === 'sig' ? 'signing' : 'published',
		createdAt: at,
		stateChangedAt: at
	};
}

function reportSigners(records: readonly Doc[]) {
	for (const record of records) {
		if (record.state === 'signing') {
			console.log(
				`root key ${String(record.kid)} (${String(record.alg)}) signs`
			);
		}
	}
}

const rootKeysLifecycle: Migration = {
	id: '2026-09-30-root-keys-lifecycle',
	description:
		"Give the root issuer's keys the lifecycle every issuer's keys follow: move them into the key area under the root owner, the key that signed per algorithm as signing and every other as published",
	reversible: false,
	rerunnable:
		'A legacy key is written with an insert that does nothing when its record already exists, and deleted only after; an algorithm that already has a migrated signer is given no second one. A run interrupted part-way re-writes nothing and finishes the rest.',
	mongodb: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for MongoDB that is the driver's `Db`.
			const db = handle as MongoHandle;
			const legacy = await db
				.collection(LEGACY_ROOT_KEYS_AREA)
				.find({})
				.toArray();
			if (legacy.length === 0) return;
			const keys = db.collection(STORE_AREAS.bucketKeys);
			const alreadySigning = (
				await keys
					.find({ bucketId: ROOT_KEY_OWNER, state: 'signing' })
					.toArray()
			).map((record) => String(record.alg));
			// Natural order is the order key selection saw, which is what decided the signer.
			const signers = rootSignersOf(
				legacy.map((jwk) => ({
					kid: String(jwk.kid),
					alg: String(jwk.alg),
					use: typeof jwk.use === 'string' ? jwk.use : undefined
				})),
				{ ordered: true, alreadySigning }
			);
			const at = new Date();
			const records = legacy.map((jwk) =>
				rootKeyRecord(jwk, signers.has(String(jwk.kid)), at)
			);
			for (const record of records) {
				await keys.updateOne(
					{ _id: record._id },
					{ $setOnInsert: record },
					{ upsert: true }
				);
			}
			for (const jwk of legacy) {
				await db.collection(LEGACY_ROOT_KEYS_AREA).deleteOne({ _id: jwk._id });
			}
			reportSigners(records);
		}
	},
	postgres: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for PostgreSQL that is Bun's SQL client.
			const sql = handle as PostgresHandle;
			// A database provisioned after this migration was declared has no legacy table at all.
			const [exists] =
				await sql`SELECT to_regclass(${LEGACY_ROOT_KEYS_AREA}) AS t`;
			if (!exists?.t) return;
			const legacyArea = sql(LEGACY_ROOT_KEYS_AREA);
			const legacy = await sql`SELECT id, doc FROM ${legacyArea}`;
			if (legacy.length === 0) return;
			const area = sql(STORE_AREAS.bucketKeys);
			const alreadySigning = (
				await sql`
					SELECT doc FROM ${area}
					WHERE doc->>'bucketId' = ${ROOT_KEY_OWNER} AND doc->>'state' = 'signing'
				`
			).map((row) => String((row.doc as Doc).alg));
			const docs: Doc[] = legacy.map((row) => ({
				...(row.doc as Doc),
				kid: row.id
			}));
			// A table has no order to recover, so the rule is the lowest kid — printed below.
			const signers = rootSignersOf(
				docs.map((jwk) => ({
					kid: String(jwk.kid),
					alg: String(jwk.alg),
					use: typeof jwk.use === 'string' ? jwk.use : undefined
				})),
				{ ordered: false, alreadySigning }
			);
			const at = new Date();
			const records = docs.map((jwk) =>
				rootKeyRecord(jwk, signers.has(String(jwk.kid)), at)
			);
			for (const record of records) {
				await sql`
					INSERT INTO ${area} (id, doc, expires_at)
					VALUES (${String(record._id)}, ${record}, NULL)
					ON CONFLICT (id) DO NOTHING
				`;
			}
			for (const row of legacy) {
				await sql`DELETE FROM ${legacyArea} WHERE id = ${String(row.id)}`;
			}
			reportSigners(records);
		}
	}
};

export const MIGRATIONS: readonly Migration[] = [
	namespacedProtectedResources,
	rootKeysLifecycle
];
