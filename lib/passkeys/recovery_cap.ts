import type { Passkey } from '../adapters/types.js';

/*
 * Whether a passkey created via self-service email recovery is still within its 72-hour phishing-resistant cooldown
 * (specs/145 Q1=A). Leaf module so sign-in, account page, and admin views can check it without importing ceremonies.
 */
export function isRecoveryCapped(
	passkey: Pick<Passkey, 'recoveredUntil'>,
	nowMs: number = Date.now()
): boolean {
	return (
		passkey.recoveredUntil !== undefined &&
		new Date(passkey.recoveredUntil).getTime() > nowMs
	);
}
