/*
 * The ordered set of schema migrations.
 *
 * Import-free, for the reason `storage_inventory.ts` is: a drift guard has to read it without a
 * datastore, and anything reaching an adapter would make that impossible.
 *
 * It ships EMPTY, and that is the point rather than an oversight. The one migration this server ever
 * had — `managedBy` to `ownerGroupId` — is retired rather than carried forward: preserving it would
 * mean porting a one-off data rewrite to a backend whose deployments cannot contain the shape it
 * looks for, and would teach every future author that historical entries belong here. What ships is
 * the machinery.
 *
 * Because the set is empty, the runner takes it as an argument instead of importing it. That is what
 * lets a fixture set cover the machinery — the same shape `validateConfiguration` uses to check a
 * candidate configuration with the production rules.
 */

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

export const MIGRATIONS: readonly Migration[] = [];
