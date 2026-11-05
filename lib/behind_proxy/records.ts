import { checkedAdapter } from '../adapters/index.js';
import {
	BehindProxySessionPayload,
	BehindProxySignInPayload
} from './payloads.js';

/* The two model areas, each checked against its schema on every read. */
export function appSessions() {
	return checkedAdapter('BehindProxySession', BehindProxySessionPayload);
}

export function pendingSignIns() {
	return checkedAdapter('BehindProxySignIn', BehindProxySignInPayload);
}

/*
 * Every write to the two areas is here, beside the accessors, so the storage guards see each one against its area
 * and its expiry (test/storage_contract/ttl_pairing.spec.ts): both areas are reaped, so every write passes one.
 */
export function saveAppSession(
	id: string,
	payload: BehindProxySessionPayload,
	expiresIn: number
): Promise<void> {
	return appSessions().upsert(id, payload, expiresIn);
}

export function savePendingSignIn(
	id: string,
	payload: BehindProxySignInPayload,
	expiresIn: number
): Promise<void> {
	return pendingSignIns().upsert(id, payload, expiresIn);
}
