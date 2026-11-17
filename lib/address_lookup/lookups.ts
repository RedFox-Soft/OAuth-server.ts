import { ApplicationConfig } from '../configs/application.js';
import { getTelemetryStateStore } from '../adapters/index.js';
import type {
	ActivityLookup,
	PersonActivityRow,
	TelemetryStateStoreInstance
} from '../adapters/types.js';
import {
	BATCH_MAX,
	BATCH_SPACING_MS,
	BATCH_TIMEOUT_MS,
	BATCHES_PER_FLUSH,
	LOOKUP_CACHE_MAX,
	LOOKUP_FLUSH_BUDGET_MS
} from '../consts/address_lookup.js';
import { isPublic, parseAddress } from '../behind_proxy/net.js';
import { now } from '../telemetry/clock.js';
import { lookUpBatch } from './batch.js';
import { dayOf, startOfDayAfter } from './days.js';
import { heldKey } from './foxtrust_key.js';

/*
 * What this process learned today, per address (research R8): the owner and location, or null for "nothing known".
 * Emptied when the UTC day changes; bounded, so a misbehaving FoxTrust cannot grow it without end.
 */
let cacheDay = '';
const cache = new Map<string, ActivityLookup | null>();
let lastBatchAt = 0;

export function forgetLookupsForTests(): void {
	cacheDay = '';
	cache.clear();
	lastBatchAt = 0;
}

function remember(address: string, lookup: ActivityLookup | null): void {
	if (cache.size < LOOKUP_CACHE_MAX || cache.has(address)) {
		cache.set(address, lookup);
	}
}

/* The only addresses that may leave this server (SI-2, research R6): on a row being written, and public. */
function sendable(address: string): boolean {
	const parsed = parseAddress(address);
	return parsed !== null && isPublic(parsed);
}

function pause(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

async function lookUp(
	addresses: readonly string[],
	key: string,
	at: Date,
	store: TelemetryStateStoreInstance
): Promise<void> {
	const day = dayOf(at);
	const deadline = Date.now() + LOOKUP_FLUSH_BUDGET_MS;
	for (
		let batch = 0;
		batch < BATCHES_PER_FLUSH && batch * BATCH_MAX < addresses.length;
		batch += 1
	) {
		// At most five requests a second for the key, across flushes.
		const wait = lastBatchAt + BATCH_SPACING_MS - Date.now();
		if (wait > 0) await pause(wait);
		const left = deadline - Date.now();
		if (left <= 0) return;
		lastBatchAt = Date.now();
		const ips = addresses.slice(batch * BATCH_MAX, (batch + 1) * BATCH_MAX);
		const answer = await lookUpBatch(
			key,
			ips,
			Math.min(BATCH_TIMEOUT_MS, left)
		);

		if (answer.kind === 'key-refused') {
			// Rotated or muted: never used again; a new one is asked for from the next UTC day (FR-005).
			await store.setLookupKey({ droppedAt: at.toISOString() });
			await store.updateRegistration({
				notBefore: startOfDayAfter(at, 1).toISOString()
			});
			return;
		}
		if (answer.kind === 'used-up') {
			await store.recordLookups({
				day,
				at: at.toISOString(),
				exhaustedDay: day
			});
			return;
		}
		if (answer.kind === 'later') return;

		let usedUp = false;
		for (const [address, entry] of answer.entries) {
			if (entry === 'quota') usedUp = true;
			else if (entry === 'invalid') remember(address, null);
			else if (!answer.allEmpty) remember(address, entry);
		}
		await store.recordLookups({
			day,
			at: at.toISOString(),
			...(answer.limit === undefined ? {} : { limit: answer.limit }),
			...(answer.remaining === undefined
				? {}
				: { remaining: answer.remaining }),
			...(usedUp ? { exhaustedDay: day } : {})
		});
		if (usedUp) return;
	}
}

/*
 * The network owner and location of the addresses on the rows about to be written (specs/136 research R4), from the
 * activity flush and nowhere else: this is the only place a person's address leaves this server, and no request ever
 * waits on it (SI-4). Rows whose address has no answer are written without one.
 *
 * Never throws and never logs: a FoxTrust that cannot be reached must look like a server with lookups off.
 */
export async function withLookups(
	rows: PersonActivityRow[],
	at: Date = now()
): Promise<PersonActivityRow[]> {
	try {
		if (!ApplicationConfig['addressLookup.enabled']) return rows;
		const wanted = [
			...new Set(
				rows.flatMap((row) =>
					row.address !== undefined && sendable(row.address)
						? [row.address]
						: []
				)
			)
		];
		if (wanted.length === 0) return rows;

		const store = getTelemetryStateStore();
		const state = await store.read();
		const key = await heldKey(state);
		if (key === null) return rows;

		const day = dayOf(at);
		if (cacheDay !== day) {
			cache.clear();
			cacheDay = day;
		}
		const missing = wanted.filter((address) => !cache.has(address));
		if (missing.length > 0 && state?.lookups?.exhaustedDay !== day) {
			await lookUp(missing, key, at, store);
		}

		return rows.map((row) => {
			const found =
				row.address === undefined ? undefined : cache.get(row.address);
			return found ? { ...row, lookup: found } : row;
		});
	} catch {
		return rows;
	}
}
