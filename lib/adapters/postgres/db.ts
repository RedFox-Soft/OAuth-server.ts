import { SQL } from 'bun';

/*
 * The PostgreSQL connection handle.
 *
 * The one thing this file must not do is connect at module scope. `lib/adapters/mongodb/db.ts` does
 * — it awaits `connect()` at the top level and throws without MONGODB_URI — and that is why
 * `lib/consts/storage_inventory.ts` has to import nothing, why the inventory's drift guard has to
 * verify production storage without a production datastore, and why the first of the three barriers
 * on GitHub issue #25 exists at all. Repeating the mistake in a second backend would double it.
 *
 * `new SQL(url)` builds a pooled handle without opening a socket; the first query connects. So the
 * whole module graph stays loadable with no PostgreSQL anywhere, and `test/storage_contract` can
 * import anything under this directory.
 *
 * The cost of that laziness is paid elsewhere, deliberately: a server pointed at a dead PostgreSQL
 * would otherwise start happily and fail on its first request, where an eagerly connecting MongoDB
 * simply refuses to start. `ping()` below is what the startup phase calls to close that gap.
 */

let handle: SQL | undefined;

/* Bounded so a stalled database produces a rejection rather than a hung request. Deliberately not
 * configurable: these are floors for correctness, not tuning knobs, and a deployment that needs
 * different pool sizing sets them in its connection URL. */
const CONNECTION_TIMEOUT_SECONDS = 10;
const IDLE_TIMEOUT_SECONDS = 30;
const MAX_CONNECTIONS = 20;

export function sql(): SQL {
	if (!handle) {
		const url = process.env.POSTGRES_URL;
		if (!url) {
			throw new Error('POSTGRES_URL must be provided as an env var');
		}
		handle = new SQL({
			url,
			max: MAX_CONNECTIONS,
			idleTimeout: IDLE_TIMEOUT_SECONDS,
			connectionTimeout: CONNECTION_TIMEOUT_SECONDS
		});
	}
	return handle;
}

/*
 * The reachability probe behind both the startup check and the readiness endpoint.
 *
 * Reads and writes nothing, so it can neither be affected by application data nor affect it, and it
 * is bounded by the connection timeout above rather than waiting indefinitely on a stalled server.
 */
export async function ping(): Promise<void> {
	await sql()`SELECT 1`;
}

/* Test- and script-only: lets a verification run against a throwaway database close its pool so the
 * process can exit, and lets a spec drop a handle built against a different URL. */
export async function close(): Promise<void> {
	if (handle) {
		await handle.close();
		handle = undefined;
	}
}
