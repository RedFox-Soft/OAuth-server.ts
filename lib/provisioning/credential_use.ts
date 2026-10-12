import { getProvisioningConnectionStore } from '../adapters/index.js';
import type {
	CredentialSlot,
	ProvisioningConnection
} from '../adapters/types.js';
import { currentFirstUse, previousOf, previousUseDue } from './overlap.js';

/*
 * Records that a connection's credential was used, as the overlap rule reads it (specs/088 R3): the current
 * value's first use, once, and the previous value's last use, at most once a minute so a directory's import
 * does not turn every request into a write. Each write touches only its own field, so it never races an
 * administrator's replacement of the credential.
 */
export async function noteCredentialUse(
	connection: ProvisioningConnection,
	slot: CredentialSlot,
	which: 'current' | 'previous',
	now: Date = new Date()
): Promise<void> {
	const store = getProvisioningConnectionStore();
	if (which === 'current') {
		if (currentFirstUse(connection, slot) === undefined) {
			await store.noteCredentialUse(connection._id, slot, 'current', now);
		}
		return;
	}
	const previous = previousOf(connection, slot);
	if (previous && previousUseDue(previous, now)) {
		await store.noteCredentialUse(connection._id, slot, 'previous', now);
	}
}
