import type { KeyringStateStoreInstance } from '../adapters/types.js';
import {
	activeKeyring,
	fingerprintOf,
	KeyringError,
	onKeyringChanged,
	type ActiveKeyring
} from './keyring.js';

/*
 * The keyring is checked against the fingerprints the database recorded before anything is sealed or opened
 * with it: the decorators await this before their first use, so a keyring that reuses a key id with different
 * bytes is refused before the first value is written, not after (specs/116 SC-006). The singleton secrets are
 * opened while configuration is still being imported, which is why waiting for lib/index.ts would be too late.
 *
 * The store arrives through a setter because this module sits below lib/adapters, which builds the stores.
 */
let stateStore: (() => KeyringStateStoreInstance) | null = null;
let checked: Promise<void> | null = null;

export function useKeyringStateStore(
	source: () => KeyringStateStoreInstance
): void {
	stateStore = source;
	checked = null;
}

onKeyringChanged(() => {
	checked = null;
});

export function keyringChecked(): Promise<void> {
	const keyring = activeKeyring();
	if (!keyring || !stateStore) return Promise.resolve();
	checked ??= check(keyring, stateStore());
	return checked;
}

async function check(
	keyring: ActiveKeyring,
	store: KeyringStateStoreInstance
): Promise<void> {
	const known = (await store.read())?.fingerprints ?? {};
	for (const [kid, key] of keyring.keys) {
		if (Object.hasOwn(known, kid) && known[kid] !== fingerprintOf(key)) {
			throw new KeyringError(
				`the keyring's key "${kid}" is not the key this database's values under "${kid}" were sealed with. Supply the original key under that id, or a new key under a new id, and start again.`
			);
		}
	}
	for (const [kid, key] of keyring.keys) {
		const fingerprint = fingerprintOf(key);
		if (Object.hasOwn(known, kid)) continue;
		if (
			(await store.addFingerprintIfAbsent(kid, fingerprint)) !== fingerprint
		) {
			throw new KeyringError(
				`another process recorded a different key under "${kid}" at the same moment; supply one keyring to every process and start again.`
			);
		}
	}
}

/* Called by lib/index.ts after the migration gate, so a refusal stops the start even when nothing was opened yet. */
export const assertKeyring = keyringChecked;

/* Test-only: the stores were replaced, so the check is made again against the new ones. */
export function resetKeyringCheckForTests(): void {
	checked = null;
}

/*
 * Records that a server-wide secret which could not be opened was replaced, for the encryption status to say
 * what that cost (specs/116 FR-017). Never fails the caller: the replacement already happened.
 */
export async function noteRegenerated(
	kind: 'errorOriginSalt' | 'dpopNonceSecret'
): Promise<void> {
	if (!stateStore) return;
	try {
		const store = stateStore();
		const regenerated = (await store.read())?.regenerated ?? {};
		await store.patch({
			regenerated: { ...regenerated, [kind]: new Date().toISOString() }
		});
	} catch {
		// The status then omits the note; the secret itself is in place.
	}
}
