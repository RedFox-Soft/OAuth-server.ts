import { selectBackend } from '../lib/adapters/selectBackend.js';

/*
 * Replaces the root signing keys the keyring cannot open (specs/116), for an operator who can no longer sign
 * in to the console because those keys sign its sign-in.
 *
 *   bun run admin:replace-root-keys
 *
 * Needs the keyring the server runs with (KEYRING or the keyring file), so the new keys are sealed with it.
 * Tokens the revoked keys signed stop verifying; relying parties fetch the new keys from the key set.
 */

if (selectBackend(process.env) === 'memory') {
	console.error(
		'no datastore is configured, so there are no stored keys to replace. Set MONGODB_URI or POSTGRES_URL.'
	);
	process.exit(1);
}

// Imported only now: the adapter index connects to the configured datastore as a side effect of import.
const { replaceRootKeys } = await import('../lib/sealing/replace_root_keys.js');

try {
	const { revoked, signing } = await replaceRootKeys();
	console.log(
		revoked.length === 0
			? 'Every root key opens with this keyring; nothing changed.'
			: `Revoked ${revoked.join(', ')}; now signing with ${signing.join(', ') || 'the remaining keys'}.`
	);
	process.exit(0);
} catch (error) {
	console.error(
		error instanceof Error
			? error.message
			: 'the root keys could not be replaced'
	);
	process.exit(1);
}
