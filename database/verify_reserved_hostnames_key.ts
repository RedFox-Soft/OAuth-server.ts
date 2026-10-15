/*
 * The reserved hostnames setting moves to the key it is shown and accepted under (specs/100), against a real
 * datastore: a stored value moves, a value already under the new key wins, and a second application changes
 * nothing. Shared by verify_mongodb.ts and verify_postgres.ts, which supply the raw reads and writes.
 */

type Doc = Record<string, unknown>;

export interface SettingsKeyHooks {
	insertSettings(id: string, config: Doc): Promise<void>;
	readSettings(id: string): Promise<Doc | null>;
	removeSettings(id: string): Promise<void>;
	/* One application of the migration's half for this backend; answers its report lines. */
	apply(): Promise<unknown>;
}

type Check = (name: string, ok: boolean, detail?: string) => void;

export async function verifyReservedHostnamesKey(
	hooks: SettingsKeyHooks,
	stamp: string,
	check: Check
): Promise<void> {
	const legacy = `fidelity-settings-legacy-${stamp}`;
	const both = `fidelity-settings-both-${stamp}`;
	await hooks.insertSettings(legacy, {
		'buckets.reservedHostnames': ['status.example.com'],
		'mcp.enabled': true
	});
	await hooks.insertSettings(both, {
		'buckets.reservedHostnames': ['old.example.com'],
		'projects.reservedHostnames': ['new.example.com']
	});

	await hooks.apply();
	const second = await hooks.apply();
	const moved = await hooks.readSettings(legacy);
	const kept = await hooks.readSettings(both);
	await hooks.removeSettings(legacy);
	await hooks.removeSettings(both);

	check(
		'the settings migration moves reserved hostnames to the projects key and keeps the other settings',
		JSON.stringify(moved) ===
			JSON.stringify({
				'mcp.enabled': true,
				'projects.reservedHostnames': ['status.example.com']
			}),
		JSON.stringify(moved)
	);
	check(
		'a value already under the projects key wins, and the second application moves nothing',
		JSON.stringify(kept) ===
			JSON.stringify({ 'projects.reservedHostnames': ['new.example.com'] }) &&
			JSON.stringify(second) === JSON.stringify(['settings keys moved: 0']),
		`${JSON.stringify(kept)}; second run ${JSON.stringify(second)}`
	);
}
