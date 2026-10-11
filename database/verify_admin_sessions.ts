import type { AdminSessionStoreInstance } from '../lib/adapters/types.js';

/*
 * Ending one administrator's console sessions, against a real datastore (specs/083): a delete by `userId`,
 * which the in-memory store performs with a scan and the database backends with the index the inventory
 * declares on the admin-session area. Shared by verify_mongodb.ts and verify_postgres.ts so both backends
 * answer the same questions in the same words.
 */
export async function verifyAdminSessionsByUser(
	store: AdminSessionStoreInstance,
	check: (name: string, ok: boolean, detail?: string) => void
): Promise<void> {
	const stamp = Date.now();
	const open = (userId: string) =>
		store.create({
			userId,
			bucketId: 'admin',
			activeGroupId: `group-${stamp}`,
			tokens: {},
			ttlSeconds: 600,
			absoluteTtlSeconds: 3600
		});
	const colleague = `recover-${stamp}`;
	const laptop = await open(colleague);
	const phone = await open(colleague);
	const someoneElse = await open(`keep-${stamp}`);

	const ended = await store.destroyByUser(colleague);
	check(
		"ending an administrator's console sessions ends every one of theirs and answers how many",
		ended === 2 &&
			(await store.find(laptop._id)) === null &&
			(await store.find(phone._id)) === null,
		`${ended}`
	);
	check(
		"ending an administrator's console sessions leaves another administrator's",
		(await store.find(someoneElse._id)) !== null
	);
	check(
		'ending the sessions of an administrator who holds none answers 0',
		(await store.destroyByUser(colleague)) === 0
	);
	await store.destroy(someoneElse._id);
}
