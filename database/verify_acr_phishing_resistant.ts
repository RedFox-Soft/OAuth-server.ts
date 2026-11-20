/*
 * The phishing-resistant authentication context (specs/142 research R6), against a real datastore: a stored
 * `acrValues` from before it is given `phr` with every other name kept, `urn:foxauth:acr:phr` when the operator already
 * uses `phr`, nothing at all when no `acrValues` is stored, and a second application changes nothing. Shared by
 * verify_mongodb.ts and verify_postgres.ts, which supply the raw reads and writes of the one settings document; it puts
 * back what it found.
 */

type Doc = Record<string, unknown>;

export interface AcrPhishingResistantHooks {
	/* null removes the settings document. */
	writeSettings(config: Doc | null): Promise<void>;
	readSettings(): Promise<Doc | null>;
	/* One application of the migration's half for this backend; answers its report lines. */
	apply(): Promise<unknown>;
}

type Check = (name: string, ok: boolean, detail?: string) => void;

/* Key order is the datastore's own (jsonb sorts keys), so documents are compared with their keys sorted. */
function sorted(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(sorted);
	if (value === null || typeof value !== 'object') return value;
	return Object.fromEntries(
		Object.entries(value)
			.sort(([a], [b]) => a.localeCompare(b))
			.map(([key, inner]) => [key, sorted(inner)])
	);
}

const same = (a: unknown, b: unknown) =>
	JSON.stringify(sorted(a)) === JSON.stringify(sorted(b));

const OWN = { password: '1', multi_factor: '2', federated: 'fed' };

export async function verifyAcrPhishingResistant(
	hooks: AcrPhishingResistantHooks,
	check: Check
): Promise<void> {
	const original = await hooks.readSettings();
	try {
		await hooks.writeSettings({ acrValues: OWN, 'mcp.enabled': true });
		const first = await hooks.apply();
		const second = await hooks.apply();
		check(
			'stored names gain phr, keep every other name, and a second application writes nothing',
			same(await hooks.readSettings(), {
				acrValues: { ...OWN, phishing_resistant: 'phr' },
				'mcp.enabled': true
			}) &&
				same(first, ['stored acrValues given phishing_resistant = phr']) &&
				same(second, ['no stored acrValues to change']),
			`${JSON.stringify(await hooks.readSettings())}; ${JSON.stringify(first)}; ${JSON.stringify(second)}`
		);

		await hooks.writeSettings({ acrValues: { ...OWN, federated: 'phr' } });
		await hooks.apply();
		check(
			'an operator who already named another context phr gets the fallback name',
			same(await hooks.readSettings(), {
				acrValues: {
					...OWN,
					federated: 'phr',
					phishing_resistant: 'urn:foxauth:acr:phr'
				}
			}),
			JSON.stringify(await hooks.readSettings())
		);

		await hooks.writeSettings({ 'mcp.enabled': true });
		const none = await hooks.apply();
		check(
			'settings with no stored acrValues are left alone',
			same(await hooks.readSettings(), { 'mcp.enabled': true }) &&
				same(none, ['no stored acrValues to change']),
			JSON.stringify(await hooks.readSettings())
		);

		await hooks.writeSettings(null);
		check(
			'an instance with no settings document has nothing to change',
			same(await hooks.apply(), ['no stored acrValues to change']) &&
				(await hooks.readSettings()) === null
		);
	} finally {
		await hooks.writeSettings(original);
	}
}
