import epochTime from '../helpers/epoch_time.js';
import { getKeyringStateStore, getSealingStore } from '../adapters/index.js';
import type {
	SealedLeaf,
	SealingPassReport,
	UnreadableSecret
} from '../adapters/types.js';
import { bindingOf, SEALED_FIELDS } from '../consts/sealed_fields.js';
import { activeKeyring, type ActiveKeyring } from './keyring.js';
import {
	isSealed,
	kidOf,
	openBytes,
	openText,
	seal,
	sealBytes
} from './seal.js';
import { keyringChecked } from './startup.js';
import { entryOf, UNREADABLE_LISTED } from './unreadable.js';

/*
 * The encryption pass (specs/116 research R8): every declared leaf, read as stored. Plaintext is sealed, a
 * value under a key that is readable but not the write key is sealed again under the write key, and what
 * cannot be opened is counted and listed. Each change is a compare-and-set of that one leaf, so an edit made
 * between the pass's read and its write is never undone.
 *
 * Without a keyring it only counts, so the status can say how much is sealed under keys this process lacks.
 */

/*
 * How long after a start the pass waits. A deploy runs the previous release beside this one for a while
 * (Fly's blue-green switch, a rolling restart), and a value sealed while the previous release still reads
 * the database is read there as plaintext: a client secret that no longer matches, an authenticator that
 * stops agreeing. Ten minutes outlasts the switch.
 */
export const PASS_DELAY_MS = 10 * 60 * 1000;

const CLAIM_ISSUER = 'keyring-pass';
const CLAIM_ID = 'pass';
const CLAIM_SECONDS = 30 * 60;

type Tally = {
	perKid: Record<string, number>;
	plaintext: number;
	unreadable: UnreadableSecret[];
	unreadableTotal: number;
};

function count(tally: Tally, kid: string): void {
	tally.perKid[kid] = (tally.perKid[kid] ?? 0) + 1;
}

async function sealedAgain(
	leaf: SealedLeaf,
	plain: string | Uint8Array
): Promise<string | Buffer> {
	const binding = bindingOf(leaf.target);
	return typeof leaf.value === 'string'
		? seal(plain, binding)
		: sealBytes(
				typeof plain === 'string' ? Buffer.from(plain) : plain,
				binding
			);
}

async function visit(
	leaf: SealedLeaf,
	keyring: ActiveKeyring | null,
	tally: Tally
): Promise<void> {
	const store = getSealingStore();
	if (!isSealed(leaf.value)) {
		if (
			keyring &&
			(await store.sealAt(
				leaf.target,
				leaf.value,
				await sealedAgain(leaf, leaf.value)
			))
		) {
			count(tally, keyring.write);
		} else {
			tally.plaintext += 1;
		}
		return;
	}
	const binding = bindingOf(leaf.target);
	const opened =
		typeof leaf.value === 'string'
			? await openText(leaf.value, binding)
			: await openBytes(leaf.value, binding);
	const kid = opened.kid ?? kidOf(leaf.value) ?? 'unknown';
	if (!opened.ok) {
		count(tally, kid);
		tally.unreadableTotal += 1;
		if (tally.unreadable.length < UNREADABLE_LISTED) {
			tally.unreadable.push(entryOf(leaf.target, opened.reason, opened.kid));
		}
		return;
	}
	if (
		keyring &&
		kid !== keyring.write &&
		(await store.sealAt(
			leaf.target,
			leaf.value,
			await sealedAgain(leaf, opened.value)
		))
	) {
		count(tally, keyring.write);
		return;
	}
	count(tally, kid);
}

export async function runPass(): Promise<SealingPassReport | null> {
	await keyringChecked();
	const keyring = activeKeyring();
	const { ReplayDetection } = await import('../models/replay_detection.js');
	if (
		!(await ReplayDetection.unique(
			CLAIM_ISSUER,
			CLAIM_ID,
			epochTime() + CLAIM_SECONDS
		))
	) {
		return null;
	}
	try {
		const tally: Tally = {
			perKid: {},
			plaintext: 0,
			unreadable: [],
			unreadableTotal: 0
		};
		const kinds = new Set(SEALED_FIELDS.map((field) => field.kind));
		for (const kind of kinds) {
			for (const leaf of await getSealingStore().scan(kind)) {
				if (!leaf.revoked) await visit(leaf, keyring, tally);
			}
		}
		const report: SealingPassReport = {
			at: new Date().toISOString(),
			mode: keyring ? 'seal' : 'count',
			...tally
		};
		await getKeyringStateStore().patch({ report });
		return report;
	} finally {
		await ReplayDetection.release(CLAIM_ISSUER, CLAIM_ID);
	}
}

let pending: Promise<SealingPassReport | null> | null = null;
let scheduled = false;

/* Whether this process has a pass waiting or running, which the status reports as pending. */
export function passScheduled(): boolean {
	return scheduled;
}

/*
 * Runs the pass after `delayMs`, in the background: a failure is reported in the log and the status keeps
 * showing the values still to seal, which the next start tries again. Never holds the process open.
 */
export function startPassSoon(delayMs: number = PASS_DELAY_MS): void {
	scheduled = true;
	pending = new Promise((resolve) => {
		const timer = setTimeout(() => {
			runPass().then(resolve, (error: unknown) => {
				console.error(
					`the encryption pass stopped: ${error instanceof Error ? error.message : String(error)}`
				);
				resolve(null);
			});
		}, delayMs);
		timer.unref();
	});
	void pending.finally(() => {
		scheduled = false;
	});
}

/* Test-only: the pass the last generation or start began, to wait for. */
export function pendingPassForTests(): Promise<SealingPassReport | null> | null {
	return pending;
}
