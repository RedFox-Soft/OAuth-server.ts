import { foxtrustKeyStore } from '../adapters/index.js';
import type { TelemetryState } from '../adapters/types.js';

/* `ftk_<12>_<43>` as FoxTrust issues it; anything else is not stored and not sent. */
const KEY_SHAPE = /^ftk_[A-Za-z0-9_-]{12}_[A-Za-z0-9_-]{43}$/;

export function isFoxTrustKey(value: unknown): value is string {
	return typeof value === 'string' && KEY_SHAPE.test(value);
}

/* Whether the state says a key is in use: received, and not dropped since (specs/136 data-model §3). */
export function keyInUse(state: TelemetryState | null): boolean {
	return (
		state?.lookupKey !== undefined && state.lookupKey.droppedAt === undefined
	);
}

/*
 * The key itself, only while one is in use and its sealed value opens. Never returned by a route, never logged
 * (SI-7): its one way out is the `authorization` header of a batch.
 */
export async function heldKey(
	state: TelemetryState | null
): Promise<string | null> {
	if (!keyInUse(state)) return null;
	const stored = await foxtrustKeyStore.read();
	if (!(stored instanceof Uint8Array) || stored.length === 0) return null;
	const key = Buffer.from(stored).toString('utf8');
	return isFoxTrustKey(key) ? key : null;
}

/*
 * Keeps a key FoxTrust issued: the first is created, a later one replaces what is stored. FoxTrust revoked the old one
 * when it issued this, so there is nothing to keep it for.
 */
export async function keepKey(key: string): Promise<void> {
	const bytes = Buffer.from(key, 'utf8');
	const stored = await foxtrustKeyStore.read();
	if (stored === null || stored === undefined) {
		await foxtrustKeyStore.create(bytes);
		return;
	}
	await foxtrustKeyStore.replace(stored, bytes);
}
