import { MIGRATIONS } from '../consts/migrations.js';
import { selectBackend } from '../adapters/selectBackend.js';
import { compare } from './state.js';

/*
 * Refuses to start against a database whose recorded migration state is not the one this release
 * expects.
 *
 * Called from the server entry, deliberately, and NOT from anything the models import. A migration
 * check reaches the adapters by definition, and `lib/configs/keystore.ts` documents what happens to a
 * module in that graph that awaits: it reorders module evaluation and trips the
 * `base_model → provider → models` cycle. The startup phase where keys load is the right neighbourhood
 * and the entry is the right file.
 *
 * Refusing is the whole behaviour — nothing here applies anything. An upgrade's data changes happen
 * when an operator chose them to, not as a side effect of a restart that might be a crash loop.
 */
export async function assertMigrationsCurrent(): Promise<void> {
	const backend = selectBackend(process.env);

	/* Nothing is persisted, so nothing can be behind. This is also what keeps the check out of the
	 * default test run, which configures no datastore. */
	if (backend === 'memory') return;

	const { getSchemaMigrationStore, storagePing } =
		await import('../adapters/index.js');

	/*
	 * Reachability first — belt and braces rather than the mechanism, and worth being accurate about.
	 *
	 * The lazy PostgreSQL handle looked like it would let a server start against a dead database and
	 * fail on the first request. Measured against a stopped container, it does not: `lib/configs/keys.ts`
	 * reads the key store while the model graph evaluates, so the boot already dies during imports —
	 * before this line, with the driver's own error.
	 *
	 * This stays because depending on that is depending on an import-order accident. Move key loading,
	 * or give a backend a lazy key store, and the gap opens again silently. What it costs is one query
	 * per start; what it buys is that the intent is written down rather than inferred.
	 *
	 * The limit is worth stating too: because the key loader gets there first, the message an operator
	 * actually sees for an unreachable datastore is the driver's, not this one's.
	 */
	try {
		await storagePing();
	} catch (error) {
		throw new Error(
			`the configured ${backend} datastore did not answer: ${(error as Error).message}`
		);
	}

	const state = compare(MIGRATIONS, await getSchemaMigrationStore().all());

	if (state.status === 'current') return;

	if (state.status === 'behind') {
		throw new Error(
			`this database is missing ${state.outstanding.length} migration(s): ` +
				`${state.outstanding.join(', ')}. Run \`bun run db:migrate\` and start again.`
		);
	}

	if (state.status === 'ahead') {
		/*
		 * An older binary against a database a newer release migrated. Starting would mean writing
		 * records in a shape the newer code governs, so the damage is silent and cumulative — worse than
		 * a refusal, which is merely inconvenient.
		 */
		throw new Error(
			`this database was migrated by a newer release than this server: ` +
				`${state.unknown.join(', ')}. Upgrade the server; do not migrate the database backwards.`
		);
	}

	throw new Error(
		`these migrations are recorded under declarations that have since changed: ` +
			`${state.mismatched.join(', ')}. A released migration must not be edited — the database's ` +
			'account of itself cannot be trusted until this is resolved.'
	);
}
