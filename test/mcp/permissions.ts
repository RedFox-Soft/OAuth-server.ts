import { mcpClientPermissionStore } from 'lib/adapters/index.ts';

/*
 * Seeding and clearing the administrative client permission list.
 *
 * A helper module rather than a `*.config.ts` export, because the harness consumes a config's named
 * exports by a fixed set of names and a permission list is not one of them — the same reason
 * `test/admin_session.ts` is a helper. Same shape as that file: a spec calls it in `beforeEach`.
 *
 * Every Story 3 spec starts from an empty list, because empty is the shipped default and a spec that
 * seeded first would never notice if that default changed (FR-021).
 */

export async function clearPermissions(): Promise<void> {
	for (const entry of await mcpClientPermissionStore.list()) {
		await mcpClientPermissionStore.destroy(entry._id);
	}
}

export async function permitIdentifier(
	identifier: string,
	opts: { requireKeyProof?: boolean; loopbackAcknowledged?: boolean } = {}
): Promise<void> {
	await mcpClientPermissionStore.create({
		_id: identifier,
		kind: 'identifier',
		requireKeyProof: opts.requireKeyProof ?? false,
		loopbackAcknowledged: opts.loopbackAcknowledged ?? false,
		acknowledgedBy: opts.loopbackAcknowledged ? 'test-admin' : undefined
	});
}

export async function permitHost(host: string): Promise<void> {
	await mcpClientPermissionStore.create({
		_id: host,
		kind: 'host',
		requireKeyProof: false,
		loopbackAcknowledged: false
	});
}
