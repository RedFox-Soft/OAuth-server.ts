import type { ProtectedResourceStoreInstance } from '../lib/adapters/types.js';

/* A value with its object keys sorted: PostgreSQL's jsonb keeps no key order, so only the content is compared. */
function canonical(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(canonical);
	if (value !== null && typeof value === 'object') {
		return Object.fromEntries(
			Object.entries(value)
				.sort(([a], [b]) => a.localeCompare(b))
				.map(([k, v]) => [k, canonical(v)])
		);
	}
	return value;
}

/*
 * Conditions on one MCP tool (specs/131) against a real datastore: a row with conditions and no scope, and an API
 * whose access holds only the time zone its rows read their hours in, are read back exactly as written. Shared by
 * verify_mongodb.ts and verify_postgres.ts so both backends answer the same questions in the same words.
 */
export async function verifyApiToolConditions(
	store: ProtectedResourceStoreInstance,
	check: (name: string, ok: boolean, detail?: string) => void
): Promise<void> {
	const stamp = Date.now();
	const namespace = `verify-tools-${stamp}`;
	const identifier = `https://tools-${stamp}.invalid/mcp`;
	const tools = {
		rows: [
			{
				name: 'delete_files',
				scopes: [],
				conditions: [
					{ kind: 'group' as const, groupIds: ['ops'] },
					{
						kind: 'time' as const,
						windows: [{ days: [0, 1, 2, 3, 4], start: 540, end: 1080 }]
					}
				]
			},
			{ name: 'search_files', scopes: ['files:read'] }
		],
		otherTools: 'refuse' as const,
		withoutMethod: 'refuse' as const,
		access: { conditions: [], timeZone: 'Europe/Berlin' }
	};

	await store.create({
		namespace,
		identifier,
		bucketId: `verify-tools-bucket-${stamp}`,
		name: 'Files',
		scopes: ['files:read']
	});
	await store.update(namespace, identifier, { tools });
	const read = await store.find(namespace, identifier);
	check(
		'a tool row with conditions and no scope, and a zone-only access, read back as written',
		JSON.stringify(canonical(read?.tools)) === JSON.stringify(canonical(tools)),
		JSON.stringify(read?.tools)
	);

	await store.destroy(namespace, identifier);
}
