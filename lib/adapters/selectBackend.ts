export type BackendName = 'memory' | 'mongodb' | 'postgres';

/*
 * Which storage backend a process uses, decided from the environment alone.
 *
 * A pure function taking the environment as an argument, for the reason `validateConfiguration` takes
 * a config object: `lib/adapters/index.ts` constructs every store as a side effect of being imported,
 * so a decision embedded there is one nothing can ask about without building all of it. Here the
 * decision is a value, and `test/storage_contract/backend_selection.spec.ts` pins every row of it.
 *
 * Configuration alone selects the backend — no build flag, no code override — which is Principle II's
 * "behavioural differences MUST be driven by configuration or adapter, never by conditional branches
 * in business logic", read from the other end.
 */
export function selectBackend(
	env: Partial<Record<string, string>>
): BackendName {
	/* An empty value is what an orchestrator produces for a variable it was never given. Reading it as
	 * a choice would refuse to start a correctly configured deployment over a templating artefact. */
	const mongo = Boolean(env.MONGODB_URI);
	const postgres = Boolean(env.POSTGRES_URL);

	/*
	 * Refusing, not preferring. A server that quietly picks one of two configured datastores presents
	 * to its operator exactly as total data loss does — it starts, it serves, and everything they had
	 * is missing — and by the time anyone looks, writes have landed in the wrong place. There is no
	 * reading of two connection strings that is safe to guess at.
	 */
	if (mongo && postgres) {
		/*
		 * The env-file hint is not padding. Bun loads `.env` and `.env.local` on its own, so the variable
		 * that triggers this is frequently one the operator cannot see in their shell — a leftover
		 * `.env.local` from the other backend is the ordinary cause, and without the hint the message
		 * reads as though the process were lying about its own environment.
		 */
		throw new Error(
			'MONGODB_URI and POSTGRES_URL are both set, and a deployment uses exactly one datastore. ' +
				'Unset whichever does not belong to this deployment and start again — checking .env and ' +
				'.env.local as well as the shell, since those are loaded automatically.'
		);
	}

	if (postgres) return 'postgres';
	if (mongo) return 'mongodb';
	return 'memory';
}
