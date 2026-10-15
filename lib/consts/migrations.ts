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

import { STORE_AREAS, userAreaFor } from './storage_inventory.js';
import {
	ADMIN_BUCKET_ID,
	DEFAULT_BUCKET_ID,
	isServedAtTheRoot,
	SUPER_ADMINS_GROUP_ID,
	SUPER_ADMINS_GROUP_NAME,
	UNASSIGNED_GROUP_ID
} from '../admin/consts.js';
import { displayNameKeyOf, membershipIdOf } from '../adapters/end_user_keys.js';
import { declarationId, ROOT_NAMESPACE } from '../resources/declaration_id.js';
import { ROOT_KEY_OWNER } from './key_owner.js';
import { FREE_PLAN_ID } from './plans.js';
import { isList, isRecord, member } from '../helpers/_/object.js';
import { auditTargetTypeFor, MIGRATION_ACTOR } from './admin_audit_routes.js';

/*
 * One backend's half of a migration.
 *
 * `apply` takes the handle as `unknown` and narrows it internally. Typing it per backend would mean
 * importing a driver type here, which would cost this module its import-freedom; one documented
 * assertion inside a step is the cheaper trade, and there is exactly one such assertion per migration
 * per backend.
 */
export interface MigrationStep {
	/*
	 * May answer report lines — what the step found and did, for the operator running it (counts, never
	 * personal data). `database/migrate.ts` prints them under the migration's id.
	 */
	readonly apply: (handle: unknown) => Promise<unknown>;
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

/*
 * Where projects lived before the bucket became the only container (specs/099). Named here, by its literal,
 * because the area is gone from the inventory: the migrations that read it are its only readers, and the
 * collection or table stays on disk, since provisioning never drops anything.
 */
export const LEGACY_PROJECTS_AREA = 'projects';

/* The part of the MongoDB driver's `Db` the step uses — declared structurally so this module imports no
 * driver. */
interface MongoHandle {
	collection(name: string): {
		find(filter: Doc): { toArray(): Promise<Doc[]> };
		findOne(filter: Doc): Promise<Doc | null>;
		updateOne(filter: Doc, update: Doc, options: Doc): Promise<unknown>;
		updateMany(filter: Doc, update: Doc): Promise<{ modifiedCount: number }>;
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
					.collection(LEGACY_PROJECTS_AREA)
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
				const project = (
					await sql`
					SELECT doc FROM ${sql(LEGACY_PROJECTS_AREA)} WHERE id = ${String(doc.projectId)}
				`
				).at(0);
				const bucketId = (project?.doc as Doc | undefined)?.bucketId;
				const bucket = (
					typeof bucketId === 'string'
						? await sql`
								SELECT doc FROM ${sql(STORE_AREAS.userBuckets)} WHERE id = ${bucketId}
							`
						: []
				).at(0);
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
			if (!exists.t) return;
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

/*
 * Bucket roles become bucket groups, and `super_admin` becomes membership of Super administrators
 * (specs/071). What follows is the decision — pure, so a spec can hold it to its promises without a
 * datastore — and then the two backends' steps that carry it out.
 */

/* What one end-user bucket's roles become. Names are trimmed; blank ones are skipped and reported. */
export interface RoleMigrationPlan {
	groups: { displayName: string; key: string; memberIds: string[] }[];
	/* Spellings folded into one group because they differ only in letter case. */
	merges: string[][];
	/* Names users held that the bucket never declared — kept as groups, so no assignment is lost. */
	undeclared: string[];
	skipped: number;
}

/* The same fold the store's unique key uses (lib/adapters/end_user_keys.ts), so the plan and the index agree. */
function foldOf(name: string): string {
	return name.normalize('NFC').toLowerCase();
}

export function planRoleMigration(
	declared: readonly unknown[] | undefined,
	users: readonly { _id: string; roles?: unknown }[]
): RoleMigrationPlan {
	let skipped = 0;
	const named = (value: unknown): string | null => {
		const name = typeof value === 'string' ? value.trim() : '';
		if (!name) {
			skipped += 1;
			return null;
		}
		return name;
	};
	const declaredSpelling = new Map<string, string>();
	for (const raw of declared ?? []) {
		const name = named(raw);
		if (name !== null && !declaredSpelling.has(foldOf(name))) {
			declaredSpelling.set(foldOf(name), name);
		}
	}
	const spellings = new Map<string, Set<string>>();
	const members = new Map<string, Set<string>>();
	for (const name of declaredSpelling.values()) {
		spellings.set(foldOf(name), new Set([name]));
		members.set(foldOf(name), new Set());
	}
	for (const user of users) {
		const held = Array.isArray(user.roles) ? user.roles : [];
		for (const raw of held) {
			const name = named(raw);
			if (name === null) continue;
			const key = foldOf(name);
			if (!spellings.has(key)) spellings.set(key, new Set());
			spellings.get(key)?.add(name);
			if (!members.has(key)) members.set(key, new Set());
			members.get(key)?.add(user._id);
		}
	}
	const groups: RoleMigrationPlan['groups'] = [];
	const merges: string[][] = [];
	const undeclared: string[] = [];
	for (const [key, names] of [...spellings].sort(([a], [b]) =>
		a < b ? -1 : 1
	)) {
		const sorted = [...names].sort();
		const displayName = declaredSpelling.get(key) ?? sorted[0];
		if (sorted.length > 1) merges.push(sorted);
		if (!declaredSpelling.has(key)) undeclared.push(displayName);
		groups.push({
			displayName,
			key,
			memberIds: [...(members.get(key) ?? [])].sort()
		});
	}
	return { groups, merges, undeclared, skipped };
}

/*
 * Which administrators become members of Super administrators: every holder of `super_admin`, active or not —
 * a deactivated one reactivated later must come back with the authority they had — and nobody else. The
 * `project_admin` holdings are only counted: the role granted nothing.
 */
export function planSuperAdmins(
	admins: readonly { _id: string; roles?: unknown }[]
): { superAdmins: string[]; projectAdmins: number } {
	const superAdmins: string[] = [];
	let projectAdmins = 0;
	for (const admin of admins) {
		const roles = Array.isArray(admin.roles) ? admin.roles : [];
		if (roles.includes('super_admin')) superAdmins.push(admin._id);
		if (roles.includes('project_admin')) projectAdmins += 1;
	}
	return { superAdmins, projectAdmins };
}

/* The report every backend's step returns: counts only. */
function roleMigrationReport(totals: {
	groups: number;
	memberships: number;
	undeclared: number;
	merges: number;
	skipped: number;
	superAdmins: number;
	projectAdmins: number;
}): string[] {
	return [
		`bucket groups created from roles: ${totals.groups}`,
		`memberships written: ${totals.memberships}`,
		`role names held but never declared, kept as groups: ${totals.undeclared}`,
		`role names merged because they differed only in letter case: ${totals.merges}`,
		`blank role names skipped: ${totals.skipped}`,
		`administrators made members of Super administrators: ${totals.superAdmins}`,
		`project_admin holdings dropped (the role granted nothing): ${totals.projectAdmins}`
	];
}

function newGroupId(): string {
	return globalThis.crypto.randomUUID().replaceAll('-', '');
}

const rolesToGroups: Migration = {
	id: '2026-10-08-roles-to-groups',
	description:
		'Bucket roles become bucket groups, and super_admin becomes membership of Super administrators',
	reversible: false,
	rerunnable:
		'Only records still carrying `roles` are read; a group is inserted only when its key is absent and a membership record only when its `_id` is absent, and a record’s `roles` is removed only after everything derived from it is written — so a run interrupted anywhere resumes, and a second run finds nothing.',
	mongodb: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for MongoDB that is the driver's `Db`.
			const db = handle as MongoHandle;
			const now = new Date();
			const totals = {
				groups: 0,
				memberships: 0,
				undeclared: 0,
				merges: 0,
				skipped: 0,
				superAdmins: 0,
				projectAdmins: 0
			};

			const adminGroups = db.collection(STORE_AREAS.groups);
			await adminGroups.updateOne(
				{ _id: SUPER_ADMINS_GROUP_ID },
				{
					$set: { name: SUPER_ADMINS_GROUP_NAME },
					$setOnInsert: {
						kind: 'system',
						members: [],
						createdAt: now,
						updatedAt: now
					}
				},
				{ upsert: true }
			);
			const admins = db.collection(userAreaFor(ADMIN_BUCKET_ID));
			const holders = await admins.find({ roles: { $exists: true } }).toArray();
			const decided = planSuperAdmins(
				holders.map((a) => ({ _id: String(a._id), roles: a.roles }))
			);
			totals.projectAdmins = decided.projectAdmins;
			for (const userId of decided.superAdmins) {
				const group = await adminGroups.findOne({ _id: SUPER_ADMINS_GROUP_ID });
				const stored = group?.members;
				const members = isList(stored) ? stored : [];
				if (!members.some((m) => member(m, 'userId') === userId)) {
					await adminGroups.updateOne(
						{ _id: SUPER_ADMINS_GROUP_ID },
						{
							$set: {
								members: [...members, { userId, role: 'member' }],
								updatedAt: now
							}
						},
						{}
					);
					totals.superAdmins += 1;
				}
			}
			/* After the memberships derived from them are written, so an interrupted run resumes. */
			for (const holder of holders) {
				await admins.updateOne(
					{ _id: holder._id },
					{ $unset: { roles: '' } },
					{}
				);
			}

			const buckets = db.collection(STORE_AREAS.userBuckets);
			const groups = db.collection(STORE_AREAS.bucketGroups);
			const memberships = db.collection(STORE_AREAS.bucketGroupMembers);
			for (const bucket of await buckets.find({}).toArray()) {
				const bucketId = String(bucket._id);
				if (bucketId !== ADMIN_BUCKET_ID) {
					const users = db.collection(userAreaFor(bucketId));
					const holders = await users
						.find({ roles: { $exists: true } })
						.toArray();
					const plan = planRoleMigration(
						Array.isArray(bucket.roles) ? bucket.roles : [],
						holders.map((u) => ({ _id: String(u._id), roles: u.roles }))
					);
					totals.undeclared += plan.undeclared.length;
					totals.merges += plan.merges.length;
					totals.skipped += plan.skipped;
					for (const planned of plan.groups) {
						const displayNameKey = displayNameKeyOf(
							bucketId,
							planned.displayName
						);
						const existing = await groups.findOne({ displayNameKey });
						let groupId = existing ? String(existing._id) : null;
						if (!groupId) {
							groupId = newGroupId();
							await groups.updateOne(
								{ displayNameKey },
								{
									$setOnInsert: {
										_id: groupId,
										bucketId,
										displayName: planned.displayName,
										displayNameKey,
										createdAt: now,
										updatedAt: now
									}
								},
								{ upsert: true }
							);
							// The upsert may have lost to another writer; take the stored id, which every writer
							// stores as a string.
							const stored = (await groups.findOne({ displayNameKey }))?._id;
							groupId = typeof stored === 'string' ? stored : groupId;
							totals.groups += 1;
						}
						for (const userId of planned.memberIds) {
							await memberships.updateOne(
								{ _id: membershipIdOf(groupId, userId) },
								{ $setOnInsert: { groupId, userId, bucketId, createdAt: now } },
								{ upsert: true }
							);
							totals.memberships += 1;
						}
					}
					/* After every membership derived from them is written, so an interrupted run resumes. */
					for (const holder of holders) {
						await users.updateOne(
							{ _id: holder._id },
							{ $unset: { roles: '' } },
							{}
						);
					}
				}
				await buckets.updateOne(
					{ _id: bucket._id },
					{ $unset: { roles: '' } },
					{}
				);
			}
			return roleMigrationReport(totals);
		}
	},
	postgres: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for PostgreSQL that is Bun's SQL client.
			const sql = handle as PostgresHandle;
			const now = new Date();
			const totals = {
				groups: 0,
				memberships: 0,
				undeclared: 0,
				merges: 0,
				skipped: 0,
				superAdmins: 0,
				projectAdmins: 0
			};
			/*
			 * Quoted, as lib/adapters/postgres/provision.ts `tableExists` explains: `to_regclass` folds a bare name to
			 * lower case, so `user_<id>` with a capital in the id would read as missing and its roles be skipped.
			 */
			const exists = async (area: string) =>
				(
					await sql`SELECT to_regclass(${`"${area.replaceAll('"', '""')}"`}) IS NOT NULL AS present`
				)[0]?.present === true;

			const adminGroups = sql(STORE_AREAS.groups);
			await sql`
				INSERT INTO ${adminGroups} (id, doc, expires_at)
				VALUES (${SUPER_ADMINS_GROUP_ID}, ${{ _id: SUPER_ADMINS_GROUP_ID, name: SUPER_ADMINS_GROUP_NAME, kind: 'system', members: [], createdAt: now, updatedAt: now }}, NULL)
				ON CONFLICT (id) DO NOTHING
			`;
			if (await exists(userAreaFor(ADMIN_BUCKET_ID))) {
				const admins = sql(userAreaFor(ADMIN_BUCKET_ID));
				const holders =
					await sql`SELECT id, doc FROM ${admins} WHERE doc ? 'roles'`;
				const decided = planSuperAdmins(
					holders.map((row) => ({
						_id: String(row.id),
						roles: (row.doc as Doc).roles
					}))
				);
				totals.projectAdmins = decided.projectAdmins;
				for (const userId of decided.superAdmins) {
					const group = (
						await sql`SELECT doc FROM ${adminGroups} WHERE id = ${SUPER_ADMINS_GROUP_ID}`
					).at(0);
					const stored = (group?.doc as Doc | undefined)?.members;
					const members = isList(stored) ? stored : [];
					if (!members.some((m) => member(m, 'userId') === userId)) {
						await sql`
							UPDATE ${adminGroups}
							SET doc = doc || ${{ members: [...members, { userId, role: 'member' }], updatedAt: now }}
							WHERE id = ${SUPER_ADMINS_GROUP_ID}
						`;
						totals.superAdmins += 1;
					}
				}
				/* After the memberships derived from them are written, so an interrupted run resumes. */
				for (const holder of holders) {
					await sql`UPDATE ${admins} SET doc = doc - 'roles' WHERE id = ${String(holder.id)}`;
				}
			}

			const buckets = sql(STORE_AREAS.userBuckets);
			const groups = sql(STORE_AREAS.bucketGroups);
			const memberships = sql(STORE_AREAS.bucketGroupMembers);
			for (const bucket of await sql`SELECT id, doc FROM ${buckets}`) {
				const bucketId = String(bucket.id);
				const doc = bucket.doc as Doc;
				if (
					bucketId !== ADMIN_BUCKET_ID &&
					(await exists(userAreaFor(bucketId)))
				) {
					const users = sql(userAreaFor(bucketId));
					const holders =
						await sql`SELECT id, doc FROM ${users} WHERE doc ? 'roles'`;
					const plan = planRoleMigration(
						Array.isArray(doc.roles) ? doc.roles : [],
						holders.map((u) => ({
							_id: String(u.id),
							roles: (u.doc as Doc).roles
						}))
					);
					totals.undeclared += plan.undeclared.length;
					totals.merges += plan.merges.length;
					totals.skipped += plan.skipped;
					for (const planned of plan.groups) {
						const displayNameKey = displayNameKeyOf(
							bucketId,
							planned.displayName
						);
						const found = async () =>
							(
								await sql`SELECT id FROM ${groups} WHERE doc->>'displayNameKey' = ${displayNameKey}`
							)[0]?.id;
						let groupId = await found();
						if (typeof groupId !== 'string') {
							const id = newGroupId();
							/* Any unique violation — the name taken meanwhile — leaves the existing group to be read back. */
							await sql`
								INSERT INTO ${groups} (id, doc, expires_at)
								VALUES (${id}, ${{ _id: id, bucketId, displayName: planned.displayName, displayNameKey, createdAt: now, updatedAt: now }}, NULL)
								ON CONFLICT DO NOTHING
							`;
							groupId = await found();
							totals.groups += 1;
						}
						for (const userId of planned.memberIds) {
							const membershipId = membershipIdOf(String(groupId), userId);
							await sql`
								INSERT INTO ${memberships} (id, doc, expires_at)
								VALUES (${membershipId}, ${{ _id: membershipId, groupId: String(groupId), userId, bucketId, createdAt: now }}, NULL)
								ON CONFLICT (id) DO NOTHING
							`;
							totals.memberships += 1;
						}
					}
					/* After every membership derived from them is written, so an interrupted run resumes. */
					for (const holder of holders) {
						await sql`UPDATE ${users} SET doc = doc - 'roles' WHERE id = ${String(holder.id)}`;
					}
				}
				await sql`UPDATE ${buckets} SET doc = doc - 'roles' WHERE id = ${bucketId}`;
			}
			return roleMigrationReport(totals);
		}
	}
};

const PERSONAL_GROUPS_SINGLE_MEMBER =
	'2026-10-09-personal-groups-single-member';

/*
 * Personal groups become personal again (specs/075). Until then a personal group could gain members, and
 * from then on nobody joins one; this repairs what the old rule left behind.
 *
 * The owner is the first member — the invariant every reader of a personal group already relies on — and
 * keeps the group and everything it owns. Everyone else is removed. A sole member left demoted by the old
 * rule is made owner again, since a personal group's one member is its owner.
 */
export interface PersonalGroupRepair {
	readonly groupId: string;
	readonly keep: { userId: string; role: 'owner' };
	readonly removed: number;
}

export function planPersonalGroupRepair(
	groups: readonly { _id: string; kind: unknown; members: unknown }[]
): PersonalGroupRepair[] {
	const plan: PersonalGroupRepair[] = [];
	for (const group of groups) {
		if (group.kind !== 'personal' || !isList(group.members)) continue;
		const [first, ...rest] = group.members;
		const userId = member(first, 'userId');
		if (typeof userId !== 'string') continue;
		if (rest.length === 0 && member(first, 'role') === 'owner') continue;
		plan.push({
			groupId: group._id,
			keep: { userId, role: 'owner' },
			removed: rest.length
		});
	}
	return plan;
}

/* Counts only: who lost access is not something the report, or the trail, records. */
export function personalGroupRepairReport(
	plan: readonly PersonalGroupRepair[]
): string[] {
	return [
		`personal groups repaired: ${String(plan.length)}`,
		`memberships removed: ${String(plan.reduce((sum, p) => sum + p.removed, 0))}`
	];
}

/*
 * The trail entry for one repaired group, as `recordAdminAudit` would have written it for the removal route —
 * which this module cannot call, being import-free. Keyed by a deterministic id so a second run inserts
 * nothing. Counts, not people: the trail records field names and counts, never values.
 */
function personalGroupRepairEntry(
	repair: PersonalGroupRepair,
	timestamp: Date
): Doc {
	return {
		_id: `${PERSONAL_GROUPS_SINGLE_MEMBER}:${repair.groupId}`,
		actorId: MIGRATION_ACTOR,
		actorEmail: MIGRATION_ACTOR,
		action: 'group.member.remove',
		targetType: auditTargetTypeFor('group.member.remove'),
		targetId: repair.groupId,
		ownerGroupId: repair.groupId,
		attributes: ['members'],
		cascade: { members: repair.removed },
		timestamp
	};
}

const personalGroupsSingleMember: Migration = {
	id: PERSONAL_GROUPS_SINGLE_MEMBER,
	description:
		'Personal groups keep only their owner: every other member is removed, one audit entry per group',
	reversible: false,
	rerunnable:
		'Only personal groups that still have more than one member, or a sole member who is not owner, are read; each one’s audit entry is inserted under a deterministic id before the group is written, so a second application inserts nothing and writes the same one-member list.',
	mongodb: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for MongoDB that is the driver's `Db`.
			const db = handle as MongoHandle;
			const now = new Date();
			const groups = db.collection(STORE_AREAS.groups);
			const audit = db.collection(STORE_AREAS.adminAudit);
			const plan = planPersonalGroupRepair(
				(await groups.find({ kind: 'personal' }).toArray()).map((g) => ({
					_id: String(g._id),
					kind: g.kind,
					members: g.members
				}))
			);
			for (const repair of plan) {
				const { _id, ...entry } = personalGroupRepairEntry(repair, now);
				await audit.updateOne(
					{ _id },
					{ $setOnInsert: entry },
					{ upsert: true }
				);
				await groups.updateOne(
					{ _id: repair.groupId, kind: 'personal' },
					{ $set: { members: [repair.keep], updatedAt: now } },
					{}
				);
			}
			return personalGroupRepairReport(plan);
		}
	},
	postgres: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for PostgreSQL that is Bun's SQL client.
			const sql = handle as PostgresHandle;
			const now = new Date();
			const groups = sql(STORE_AREAS.groups);
			const audit = sql(STORE_AREAS.adminAudit);
			const rows =
				await sql`SELECT id, doc FROM ${groups} WHERE doc->>'kind' = 'personal'`;
			const plan = planPersonalGroupRepair(
				rows.map((row) => ({
					_id: String(row.id),
					kind: (row.doc as Doc).kind,
					members: (row.doc as Doc).members
				}))
			);
			for (const repair of plan) {
				const entry = personalGroupRepairEntry(repair, now);
				await sql`
					INSERT INTO ${audit} (id, doc, expires_at)
					VALUES (${entry._id}, ${entry}, NULL)
					ON CONFLICT (id) DO NOTHING
				`;
				await sql`
					UPDATE ${groups}
					SET doc = doc || ${{ members: [repair.keep], updatedAt: now }}
					WHERE id = ${repair.groupId} AND doc->>'kind' = 'personal'
				`;
			}
			return personalGroupRepairReport(plan);
		}
	}
};

/*
 * Static SCIM tokens get a lifetime (specs/088 US2; RFC 7644 §7.4: "Bearer tokens MUST have a limited
 * lifetime"). Every token issued from now on carries an expiry; this gives one to each token issued before,
 * without refusing any of them on the day of the upgrade: one year after it was issued, but never sooner
 * than 90 days after the upgrade. A token whose issue time is unknown is treated as old, so it gets the 90
 * days. A data change rather than a read-time default, because a default computed on read would expire every
 * token older than a year at once.
 */
const STATIC_TOKEN_EXPIRY = '2026-10-12-static-token-expiry';
const DAY_MS = 24 * 60 * 60 * 1000;
export const STATIC_TOKEN_BACKFILL_LIFETIME_DAYS = 365;
export const STATIC_TOKEN_BACKFILL_FLOOR_DAYS = 90;

export interface StaticTokenExpiryPlan {
	readonly connectionId: string;
	readonly expiresAt: Date;
}

/* A stored time as either backend hands it back: a Date from MongoDB, an ISO string from a jsonb document. */
function timeOf(value: unknown): Date | undefined {
	if (value instanceof Date) return value;
	if (typeof value === 'string') {
		const parsed = new Date(value);
		return Number.isNaN(parsed.getTime()) ? undefined : parsed;
	}
	return undefined;
}

export function planStaticTokenExpiry(
	connections: readonly {
		_id: string;
		staticTokenDigest: unknown;
		staticTokenIssuedAt: unknown;
		staticTokenExpiresAt: unknown;
	}[],
	now: Date
): StaticTokenExpiryPlan[] {
	const floor = now.getTime() + STATIC_TOKEN_BACKFILL_FLOOR_DAYS * DAY_MS;
	const plan: StaticTokenExpiryPlan[] = [];
	for (const connection of connections) {
		if (typeof connection.staticTokenDigest !== 'string') continue;
		if (timeOf(connection.staticTokenExpiresAt)) continue;
		const issuedAt = timeOf(connection.staticTokenIssuedAt);
		const yearAfterIssue = issuedAt
			? issuedAt.getTime() + STATIC_TOKEN_BACKFILL_LIFETIME_DAYS * DAY_MS
			: Number.NEGATIVE_INFINITY;
		plan.push({
			connectionId: connection._id,
			expiresAt: new Date(Math.max(yearAfterIssue, floor))
		});
	}
	return plan;
}

function staticTokenExpiryReport(
	plan: readonly StaticTokenExpiryPlan[]
): string[] {
	return [`static tokens given an expiry: ${String(plan.length)}`];
}

const staticTokenExpiry: Migration = {
	id: STATIC_TOKEN_EXPIRY,
	description:
		'Give every SCIM static token issued without an expiry one: a year after its issue, and never sooner than 90 days from now',
	reversible: false,
	rerunnable:
		'Only connections holding a static token with no expiry are read, and each write is conditional on the expiry still being absent, so a second application finds nothing to plan and writes nothing.',
	mongodb: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for MongoDB that is the driver's `Db`.
			const db = handle as MongoHandle;
			const connections = db.collection(STORE_AREAS.provisioningConnections);
			const lacking = { staticTokenExpiresAt: { $not: { $type: 'date' } } };
			const plan = planStaticTokenExpiry(
				(
					await connections
						.find({ staticTokenDigest: { $type: 'string' }, ...lacking })
						.toArray()
				).map((c) => ({
					_id: String(c._id),
					staticTokenDigest: c.staticTokenDigest,
					staticTokenIssuedAt: c.staticTokenIssuedAt,
					staticTokenExpiresAt: c.staticTokenExpiresAt
				})),
				new Date()
			);
			for (const entry of plan) {
				await connections.updateOne(
					{ _id: entry.connectionId, ...lacking },
					{ $set: { staticTokenExpiresAt: entry.expiresAt } },
					{}
				);
			}
			return staticTokenExpiryReport(plan);
		}
	},
	postgres: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for PostgreSQL that is Bun's SQL client.
			const sql = handle as PostgresHandle;
			const area = sql(STORE_AREAS.provisioningConnections);
			const rows = await sql`
				SELECT id, doc FROM ${area}
				WHERE jsonb_typeof(doc->'staticTokenDigest') = 'string'
					AND jsonb_typeof(doc->'staticTokenExpiresAt') IS DISTINCT FROM 'string'
			`;
			const plan = planStaticTokenExpiry(
				rows.map((row) => {
					const doc = row.doc as Doc;
					return {
						_id: String(row.id),
						staticTokenDigest: doc.staticTokenDigest,
						staticTokenIssuedAt: doc.staticTokenIssuedAt,
						staticTokenExpiresAt: doc.staticTokenExpiresAt
					};
				}),
				new Date()
			);
			for (const entry of plan) {
				await sql`
					UPDATE ${area}
					SET doc = doc || ${{ staticTokenExpiresAt: entry.expiresAt }}
					WHERE id = ${entry.connectionId}
						AND jsonb_typeof(doc->'staticTokenExpiresAt') IS DISTINCT FROM 'string'
				`;
			}
			return staticTokenExpiryReport(plan);
		}
	}
};

/*
 * Every project names its bucket (specs/098). A project that named none signed people into the Default bucket,
 * so writing the Default bucket into it changes nobody's sign-in — the resolver treats a project on the Default
 * bucket as it treated one with no bucket — and leaves one spelling of that state instead of two. A document
 * written before the field existed has no key at all, which both halves select alongside an explicit null.
 */
function projectsGivenABucketReport(count: number): string[] {
	return [`projects given the default bucket: ${String(count)}`];
}

const projectsRequireBucket: Migration = {
	id: '2026-10-15-projects-require-bucket',
	description:
		'Give every project that names no bucket the default bucket, which is where its clients already sign people in',
	reversible: false,
	rerunnable:
		'Only projects whose bucket is null or absent are written, and every write sets one, so a second application selects nothing.',
	mongodb: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for MongoDB that is the driver's `Db`.
			const db = handle as MongoHandle;
			const result = await db
				.collection(LEGACY_PROJECTS_AREA)
				.updateMany(
					{ bucketId: null },
					{ $set: { bucketId: DEFAULT_BUCKET_ID, updatedAt: new Date() } }
				);
			return projectsGivenABucketReport(result.modifiedCount);
		}
	},
	postgres: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for PostgreSQL that is Bun's SQL client.
			const sql = handle as PostgresHandle;
			const rows = await sql`
				UPDATE ${sql(LEGACY_PROJECTS_AREA)}
				SET doc = doc || ${{ bucketId: DEFAULT_BUCKET_ID, updatedAt: new Date() }}
				WHERE doc->'bucketId' IS NULL OR doc->'bucketId' = 'null'::jsonb
				RETURNING id
			`;
			return projectsGivenABucketReport(rows.length);
		}
	}
};

/*
 * The bucket becomes the only container (specs/099). Every fact a project held moves to what it held: its
 * bucket and its origins to each of its clients, its bucket to each of its declarations. A self-registered
 * client's `registeredAtBucket` becomes the same `bucketId`.
 *
 * Planned once from the projects as stored, then applied per backend, so both halves decide alike. The plan
 * refuses before anything is written when a client is listed by projects on different buckets: there is no
 * bucket it could honestly be given, and the server reading it today answers arbitrarily.
 *
 * A client listed by a project on the Default bucket that belonged to a tenant group has its stored consent
 * waiver cleared. It changes no sign-in: since 0.7.0 the waiver was honoured only in a bucket owned by the
 * project's group, and the Default bucket is the System group's. Once projects are gone that check has nothing
 * to read, so the stored flag must already say what the server did.
 */
interface ClientPlan {
	readonly bucketId: string;
	readonly corsOrigins: readonly string[];
	readonly requireConsent: boolean;
}

interface ProjectRemovalPlan {
	readonly clients: ReadonlyMap<string, ClientPlan>;
	readonly resourceBuckets: ReadonlyMap<string, string>;
	readonly report: string[];
}

function stringsOf(value: unknown): string[] {
	return isList(value)
		? value.filter((item): item is string => typeof item === 'string')
		: [];
}

function createdOf(project: Doc): number {
	const created = project.createdAt;
	if (created instanceof Date) return created.getTime();
	if (typeof created === 'string') return Date.parse(created) || 0;
	return 0;
}

function planProjectRemoval(
	projects: readonly Doc[],
	declaringProjectIds: readonly string[]
): ProjectRemovalPlan {
	const ordered = [...projects].sort(
		(a, b) =>
			createdOf(a) - createdOf(b) || String(a._id).localeCompare(String(b._id))
	);
	const bucketsOf = new Map<string, Set<string>>();
	const clients = new Map<string, ClientPlan>();
	const resourceBuckets = new Map<string, string>();
	const projectsPerBucket = new Map<string, string[]>();
	let sharedOneBucket = 0;

	for (const project of ordered) {
		const bucketId = project.bucketId;
		if (typeof bucketId !== 'string') continue;
		const projectId = String(project._id);
		resourceBuckets.set(projectId, bucketId);
		projectsPerBucket.set(bucketId, [
			...(projectsPerBucket.get(bucketId) ?? []),
			projectId
		]);
		const requireConsent =
			bucketId === DEFAULT_BUCKET_ID &&
			project.ownerGroupId !== UNASSIGNED_GROUP_ID;
		for (const clientId of stringsOf(project.clientIds)) {
			const seen = bucketsOf.get(clientId) ?? new Set<string>();
			seen.add(bucketId);
			bucketsOf.set(clientId, seen);
			const earlier = clients.get(clientId);
			if (earlier) {
				sharedOneBucket += 1;
				clients.set(clientId, {
					...earlier,
					requireConsent: earlier.requireConsent || requireConsent
				});
				continue;
			}
			clients.set(clientId, {
				bucketId,
				corsOrigins: stringsOf(project.corsOrigins),
				requireConsent
			});
		}
	}

	const ambiguous = [...bucketsOf]
		.filter(([, buckets]) => buckets.size > 1)
		.map(([clientId]) => clientId);
	if (ambiguous.length > 0) {
		throw new Error(
			`clients listed by projects on different buckets, so none can be given one: ${ambiguous.join(', ')} — remove each from all projects but one, then run again`
		);
	}

	const declaring = new Set(declaringProjectIds);
	const widened = [...projectsPerBucket.values()].filter(
		(ids) => ids.length > 1 && ids.some((id) => declaring.has(id))
	).length;
	return {
		clients,
		resourceBuckets,
		report: [
			`clients listed by several projects of one bucket (origins taken from the earliest): ${String(sharedOneBucket)}`,
			`buckets where machine tokens now reach every administrator-created client: ${String(widened)}`
		]
	};
}

/*
 * The client's payload after the change, or null when it is already there. Every write is conditional on
 * the target being absent, which is what makes a second application change nothing.
 */
function migratedClient(
	payload: Doc,
	plan: ClientPlan | undefined
): Doc | null {
	const next: Doc = { ...payload };
	let changed = false;
	if (plan) {
		if (next.bucketId === undefined) {
			next.bucketId = plan.bucketId;
			changed = true;
		}
		if (plan.corsOrigins.length > 0 && next.corsOrigins === undefined) {
			next.corsOrigins = [...plan.corsOrigins];
			changed = true;
		}
		if (plan.requireConsent && next['consent.require'] !== true) {
			next['consent.require'] = true;
			changed = true;
		}
	}
	if (typeof next.registeredAtBucket === 'string') {
		next.bucketId ??= next.registeredAtBucket;
		delete next.registeredAtBucket;
		changed = true;
	}
	return changed ? next : null;
}

function resourceBucketOf(
	doc: Doc,
	plan: ProjectRemovalPlan
): { bucketId: string; orphaned: boolean } {
	if (typeof doc.bucketId === 'string') {
		return { bucketId: doc.bucketId, orphaned: false };
	}
	const fromProject = plan.resourceBuckets.get(String(doc.projectId));
	if (fromProject) return { bucketId: fromProject, orphaned: false };
	const namespace = doc.namespace;
	return {
		bucketId:
			typeof namespace === 'string' && namespace !== ROOT_NAMESPACE
				? namespace
				: DEFAULT_BUCKET_ID,
		orphaned: true
	};
}

interface RemovalCounts {
	clients: number;
	ghosts: number;
	consent: number;
	resources: number;
	orphans: number;
}

function countClientChange(counts: RemovalCounts, before: Doc, next: Doc) {
	if (before.bucketId === undefined && next.bucketId !== undefined) {
		counts.clients += 1;
	}
	if (before['consent.require'] !== true && next['consent.require'] === true) {
		counts.consent += 1;
	}
}

function projectRemovalReport(
	plan: ProjectRemovalPlan,
	counts: RemovalCounts
): string[] {
	return [
		`clients given their bucket: ${String(counts.clients)}`,
		`client ids listed by a project with no stored client: ${String(counts.ghosts)}`,
		`clients whose stored consent waiver was cleared (not honoured since 0.7.0, so no sign-in changes): ${String(counts.consent)}`,
		`declarations given their bucket: ${String(counts.resources)}`,
		`declarations whose project was missing: ${String(counts.orphans)}`,
		...plan.report
	];
}

/* A client is a model document: its fields are under `payload` on both backends. */
const CLIENT_AREA = 'Client';

const removeProjects: Migration = {
	id: '2026-10-16-remove-projects',
	description:
		'Move what each project held to its clients and declarations — the bucket and the allowed origins — and retire projects',
	reversible: false,
	rerunnable:
		'A client or declaration gains a bucket only where it has none, a client gains origins only where it has none, and a dynamic client loses `registeredAtBucket` only once it is copied; the plan is read from the projects, which are never written, so a second application finds nothing to change.',
	mongodb: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for MongoDB that is the driver's `Db`.
			const db = handle as MongoHandle;
			const resources = db.collection(STORE_AREAS.protectedResources);
			const unmigrated = await resources
				.find({ projectId: { $exists: true } })
				.toArray();
			const plan = planProjectRemoval(
				await db.collection(LEGACY_PROJECTS_AREA).find({}).toArray(),
				unmigrated.map((doc) => String(doc.projectId))
			);
			const counts: RemovalCounts = {
				clients: 0,
				ghosts: 0,
				consent: 0,
				resources: 0,
				orphans: 0
			};
			const area = db.collection(CLIENT_AREA);
			const dynamic = await area
				.find({ 'payload.registeredAtBucket': { $exists: true } })
				.toArray();
			const ids = new Set([
				...plan.clients.keys(),
				...dynamic.map((doc) => String(doc._id))
			]);
			for (const id of ids) {
				const stored = await area.findOne({ _id: id });
				const before = member(stored, 'payload');
				if (!isRecord(before)) {
					counts.ghosts += 1;
					continue;
				}
				const next = migratedClient(before, plan.clients.get(id));
				if (!next) continue;
				countClientChange(counts, before, next);
				// The whole payload: `consent.require` is one key with a dot in it, which a `$set` path would split.
				await area.updateOne({ _id: id }, { $set: { payload: next } }, {});
			}
			for (const doc of unmigrated) {
				const { bucketId, orphaned } = resourceBucketOf(doc, plan);
				await resources.updateOne(
					{ _id: doc._id },
					{ $set: { bucketId }, $unset: { projectId: '' } },
					{}
				);
				counts.resources += 1;
				if (orphaned) counts.orphans += 1;
			}
			return projectRemovalReport(plan, counts);
		}
	},
	postgres: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for PostgreSQL that is Bun's SQL client.
			const sql = handle as PostgresHandle;
			const present = await sql`
				SELECT 1 FROM information_schema.tables WHERE table_name = ${LEGACY_PROJECTS_AREA}
			`;
			const projects =
				present.length === 0
					? []
					: (await sql`SELECT doc FROM ${sql(LEGACY_PROJECTS_AREA)}`).map(
							(row) => row.doc as Doc
						);
			const resourceArea = sql(STORE_AREAS.protectedResources);
			const unmigrated = await sql`
				SELECT id, doc FROM ${resourceArea} WHERE doc ? 'projectId'
			`;
			const plan = planProjectRemoval(
				projects,
				unmigrated.map((row) => String((row.doc as Doc).projectId))
			);
			const counts: RemovalCounts = {
				clients: 0,
				ghosts: 0,
				consent: 0,
				resources: 0,
				orphans: 0
			};
			const area = sql(CLIENT_AREA);
			const dynamic = await sql`
				SELECT id FROM ${area} WHERE payload ? 'registeredAtBucket'
			`;
			const ids = new Set([
				...plan.clients.keys(),
				...dynamic.map((row) => String(row.id))
			]);
			for (const id of ids) {
				const stored = (
					await sql`SELECT payload FROM ${area} WHERE id = ${id}`
				).at(0);
				const before = member(stored, 'payload');
				if (!isRecord(before)) {
					counts.ghosts += 1;
					continue;
				}
				const next = migratedClient(before, plan.clients.get(id));
				if (!next) continue;
				countClientChange(counts, before, next);
				await sql`UPDATE ${area} SET payload = ${next} WHERE id = ${id}`;
			}
			for (const row of unmigrated) {
				const { bucketId, orphaned } = resourceBucketOf(row.doc as Doc, plan);
				await sql`
					UPDATE ${resourceArea} SET doc = (doc - 'projectId') || ${{ bucketId }}
					WHERE id = ${String(row.id)}
				`;
				counts.resources += 1;
				if (orphaned) counts.orphans += 1;
			}
			return projectRemovalReport(plan, counts);
		}
	}
};

/*
 * The setting that named buckets is named for projects (specs/100). Its key is at once the configuration key,
 * the settings API's key and the stored key, so it is moved once rather than translated in each of those
 * places forever. A value already stored under the new key wins: it can only have been written by an
 * operator after the rename.
 */
const LEGACY_RESERVED_HOSTNAMES_KEY = 'buckets.reservedHostnames';
const RESERVED_HOSTNAMES_KEY = 'projects.reservedHostnames';

function movedSettings(config: Doc): Doc | null {
	if (!(LEGACY_RESERVED_HOSTNAMES_KEY in config)) return null;
	const { [LEGACY_RESERVED_HOSTNAMES_KEY]: value, ...rest } = config;
	return RESERVED_HOSTNAMES_KEY in rest
		? rest
		: { ...rest, [RESERVED_HOSTNAMES_KEY]: value };
}

function settingsMovedReport(count: number): string[] {
	return [`settings keys moved: ${String(count)}`];
}

const projectsReservedHostnames: Migration = {
	id: '2026-10-17-projects-reserved-hostnames',
	description:
		'Store the reserved hostnames setting under projects.reservedHostnames, the name it is shown and accepted under',
	reversible: false,
	rerunnable:
		'Only a settings document still holding buckets.reservedHostnames is written, and the write removes that key, so a second application finds nothing to move.',
	mongodb: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for MongoDB that is the driver's `Db`.
			const db = handle as MongoHandle;
			const area = db.collection(STORE_AREAS.serviceConfig);
			/*
			 * Read whole and rewritten whole: the key holds a dot, which a MongoDB filter or `$unset` would read as
			 * a path into a nested document that does not exist.
			 */
			let moved = 0;
			for (const doc of await area
				.find({ config: { $type: 'object' } })
				.toArray()) {
				const config = member(doc, 'config');
				const next = isRecord(config) ? movedSettings(config) : null;
				if (!next) continue;
				await area.updateOne({ _id: doc._id }, { $set: { config: next } }, {});
				moved += 1;
			}
			return settingsMovedReport(moved);
		}
	},
	postgres: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for PostgreSQL that is Bun's SQL client.
			const sql = handle as PostgresHandle;
			const area = sql(STORE_AREAS.serviceConfig);
			const rows = await sql`
				SELECT id, doc FROM ${area} WHERE doc ? ${LEGACY_RESERVED_HOSTNAMES_KEY}
			`;
			let moved = 0;
			for (const row of rows) {
				const next = isRecord(row.doc) ? movedSettings(row.doc) : null;
				if (!next) continue;
				await sql`UPDATE ${area} SET doc = ${next} WHERE id = ${String(row.id)}`;
				moved += 1;
			}
			return settingsMovedReport(moved);
		}
	}
};

/*
 * Every project records its plan (specs/102). The plan a bucket is on is recorded rather than implied, so that making
 * another plan the default moves no existing project; a bucket created from now on records the default when it is
 * created, and this gives every bucket that predates plans the one plan there was — Free. A bucket of the System
 * group carries no plan and is left alone.
 *
 * `free` rather than a catalogue read: no catalogue can be stored before the release that brings this migration, so
 * the built-in catalogue is the one in force and Free is its default.
 */
function plansRecordedReport(count: number): string[] {
	return [`projects given the Free plan: ${String(count)}`];
}

const projectsRecordPlan: Migration = {
	id: '2026-10-18-projects-record-plan',
	description:
		'Record the Free plan on every project outside the System team, so its plan is stored rather than implied',
	reversible: false,
	rerunnable:
		'Only projects with no recorded plan are written, and every write records one, so a second application selects nothing.',
	mongodb: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for MongoDB that is the driver's `Db`.
			const db = handle as MongoHandle;
			const result = await db.collection(STORE_AREAS.userBuckets).updateMany(
				{
					ownerGroupId: { $ne: UNASSIGNED_GROUP_ID },
					planId: { $exists: false }
				},
				{ $set: { planId: FREE_PLAN_ID } }
			);
			return plansRecordedReport(result.modifiedCount);
		}
	},
	postgres: {
		async apply(handle) {
			// The runner passes the selected backend's handle; for PostgreSQL that is Bun's SQL client.
			const sql = handle as PostgresHandle;
			const rows = await sql`
				UPDATE ${sql(STORE_AREAS.userBuckets)}
				SET doc = doc || ${{ planId: FREE_PLAN_ID }}
				WHERE doc->>'ownerGroupId' IS DISTINCT FROM ${UNASSIGNED_GROUP_ID}
					AND NOT (doc ? 'planId')
				RETURNING id
			`;
			return plansRecordedReport(rows.length);
		}
	}
};

export const MIGRATIONS: readonly Migration[] = [
	namespacedProtectedResources,
	rootKeysLifecycle,
	rolesToGroups,
	personalGroupsSingleMember,
	staticTokenExpiry,
	projectsRequireBucket,
	removeProjects,
	projectsReservedHostnames,
	projectsRecordPlan
];
