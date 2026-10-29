import { getKeyringStateStore } from '../adapters/index.js';
import type { UnreadableSecret } from '../adapters/types.js';
import { bindingOf, type SealTarget } from '../consts/sealed_fields.js';
import { activeKeyring, keyringSource, type KeyringSource } from './keyring.js';
import {
	repairedSince,
	unreadableNow,
	UNREADABLE_LISTED
} from './unreadable.js';
import { passScheduled } from './pass.js';

/*
 * What a super administrator is told about encryption at rest (specs/116 FR-018): derived on each read from
 * the keyring this process holds, the state the database keeps, and what this process failed to open since
 * it started. Never key material and never a secret.
 */
export interface KeyringStatus {
	state: 'none' | 'generated-not-applied' | 'in-use';
	source?: KeyringSource;
	writeKid?: string;
	kids: { kid: string; inKeyring: boolean; values: number }[];
	plaintext: number;
	unreadable: UnreadableSecret[];
	unreadableTotal: number;
	backupConfirmed: { at: string } | null;
	lastPassAt: string | null;
	passPending: boolean;
	regenerated: {
		errorOriginSalt?: string;
		dpopNonceSecret?: string;
		note: string;
	} | null;
}

/* One entry per key rather than one per private member: the repair is the same, and so is the reader's question. */
function bindingOfEntry(entry: UnreadableSecret): string {
	if (entry.kind === 'privateKey') return `bucketKeys/${entry.owner.keyId}/`;
	return bindingOf({ kind: entry.kind, ...entry.owner } as SealTarget);
}

export async function keyringStatus(): Promise<KeyringStatus> {
	const stored = await getKeyringStateStore().read();
	const keyring = activeKeyring();
	const report = stored?.report;
	const reportAt = report ? Date.parse(report.at) : 0;

	const unreadable = new Map<string, UnreadableSecret>();
	for (const entry of report?.unreadable ?? []) {
		const binding = bindingOfEntry(entry);
		if (!repairedSince(binding, reportAt)) unreadable.set(binding, entry);
	}
	const live = unreadableNow();
	for (const entry of live.entries)
		unreadable.set(bindingOfEntry(entry), entry);
	// The report lists at most UNREADABLE_LISTED; the ones it only counted are still owed to the total.
	const unlisted = report
		? Math.max(0, report.unreadableTotal - report.unreadable.length)
		: 0;
	const unreadableTotal =
		unreadable.size + unlisted + Math.max(0, live.total - live.entries.length);

	const counts = new Map<string, number>(Object.entries(report?.perKid ?? {}));
	for (const kid of keyring?.keys.keys() ?? []) {
		if (!counts.has(kid)) counts.set(kid, 0);
	}

	const state: KeyringStatus['state'] = keyring
		? 'in-use'
		: stored?.generated && !stored.generated.applied
			? 'generated-not-applied'
			: 'none';
	const regenerated = stored?.regenerated;
	const source = keyringSource();

	return {
		state,
		...(source ? { source } : {}),
		...(keyring ? { writeKid: keyring.write } : {}),
		kids: [...counts].map(([kid, values]) => ({
			kid,
			inKeyring: keyring?.keys.has(kid) ?? false,
			values
		})),
		plaintext: report?.plaintext ?? 0,
		unreadable: [...unreadable.values()].slice(0, UNREADABLE_LISTED),
		unreadableTotal,
		backupConfirmed: stored?.backupConfirmed
			? { at: stored.backupConfirmed.at }
			: null,
		lastPassAt: report?.at ?? null,
		passPending:
			keyring !== null &&
			(passScheduled() || !report || report.mode !== 'seal'),
		regenerated:
			regenerated && Object.keys(regenerated).length > 0
				? {
						...regenerated,
						note: [
							regenerated.errorOriginSalt
								? 'the error-log address key was regenerated: error records written before it no longer correlate with later ones'
								: null,
							regenerated.dpopNonceSecret
								? 'the DPoP nonce secret was regenerated: clients holding a nonce were asked for a fresh one once'
								: null
						]
							.filter(Boolean)
							.join('; ')
					}
				: null
	};
}
