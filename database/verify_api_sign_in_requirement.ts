import type { ProtectedResourceStoreInstance } from '../lib/adapters/types.js';

/*
 * An API's sign-in requirement (specs/130) against a real datastore: both fields are written on a declaration, read
 * back as they were written, and removed by a patch's `false` and `null` rather than stored as a "no" an older
 * reader could take for something else. Shared by verify_mongodb.ts and verify_postgres.ts so both backends answer
 * the same questions in the same words.
 */
export async function verifyApiSignInRequirement(
	store: ProtectedResourceStoreInstance,
	check: (name: string, ok: boolean, detail?: string) => void
): Promise<void> {
	const stamp = Date.now();
	const namespace = `verify-sign-in-${stamp}`;
	const identifier = `https://sign-in-${stamp}.invalid/mcp`;

	await store.create({
		namespace,
		identifier,
		bucketId: `verify-sign-in-bucket-${stamp}`,
		name: 'Files',
		scopes: ['files:read'],
		requireCode: true,
		signInEveryMinutes: 1440
	});
	const declared = await store.find(namespace, identifier);
	check(
		'an API declared with a sign-in requirement reads it back',
		declared?.requireCode === true && declared.signInEveryMinutes === 1440,
		JSON.stringify(declared)
	);

	await store.update(namespace, identifier, { signInEveryMinutes: 120 });
	const shortened = await store.find(namespace, identifier);
	check(
		'changing the interval keeps the code requirement',
		shortened?.requireCode === true && shortened.signInEveryMinutes === 120,
		JSON.stringify(shortened)
	);

	await store.update(namespace, identifier, {
		requireCode: false,
		signInEveryMinutes: null
	});
	const cleared = await store.find(namespace, identifier);
	check(
		'clearing the requirement removes both fields instead of storing a no',
		cleared !== null &&
			!('requireCode' in cleared) &&
			!('signInEveryMinutes' in cleared),
		JSON.stringify(cleared)
	);

	await store.destroy(namespace, identifier);
}
