import { KEY_ID_PATTERN } from '../../sealing/keyring.js';
import type {
	KeyringState,
	KeyringStatePatch,
	KeyringStateStoreInstance
} from '../types.js';

/*
 * The in-memory keyring state. Single-process by construction: nothing yields between a check and its write,
 * so the insert-if-absent the persistent backends express as a conditional write comes free.
 */
export class KeyringStateStore implements KeyringStateStoreInstance {
	private state: KeyringState | null = null;

	async read(): Promise<KeyringState | null> {
		return this.state ? structuredClone(this.state) : null;
	}

	async addFingerprintIfAbsent(
		kid: string,
		fingerprint: string
	): Promise<string> {
		// Refused here as the persistent backends refuse it, so a test cannot pass on a key id production rejects.
		if (!KEY_ID_PATTERN.test(kid)) throw new Error(`not a key id: ${kid}`);
		this.state ??= { fingerprints: {} };
		this.state.fingerprints[kid] ??= fingerprint;
		return this.state.fingerprints[kid];
	}

	async patch(fields: KeyringStatePatch): Promise<void> {
		const next: Record<string, unknown> = {
			...(this.state ?? { fingerprints: {} })
		};
		for (const [name, value] of Object.entries(fields)) {
			if (value === null) delete next[name];
			else next[name] = structuredClone(value);
		}
		this.state = next as KeyringState;
	}
}
