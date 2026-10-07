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
	isServedAtTheRoot,
	SUPER_ADMINS_GROUP_ID,
	SUPER_ADMINS_GROUP_NAME
} from '../admin/consts.js';
import { displayNameKeyOf, membershipIdOf } from '../adapters/end_user_keys.js';
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
				const members = Array.isArray(group?.members) ? group.members : [];
				if (!members.some((m: Doc) => m.userId === userId)) {
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
							groupId = String(
								(await groups.findOne({ displayNameKey }))?._id ?? groupId
							);
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
					const [group] =
						await sql`SELECT doc FROM ${adminGroups} WHERE id = ${SUPER_ADMINS_GROUP_ID}`;
					const stored = (group?.doc as Doc | undefined)?.members;
					const members = Array.isArray(stored) ? stored : [];
					if (!members.some((m: Doc) => m.userId === userId)) {
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

export const MIGRATIONS: readonly Migration[] = [
	namespacedProtectedResources,
	rootKeysLifecycle,
	rolesToGroups
];
