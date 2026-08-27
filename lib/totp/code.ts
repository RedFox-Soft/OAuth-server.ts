import crypto from 'node:crypto';

import { DIGITS, DRIFT_STEPS, STEP_SECONDS } from './consts.js';

/*
 * HOTP (RFC 4226) and TOTP (RFC 6238), and nothing else. No clock, no storage, no I/O — the time is
 * an argument, which is what makes the RFC 6238 Appendix B vectors testable with no fake clock and no
 * injected time source (test/totp/algorithm.spec.ts).
 *
 * HMAC-SHA1 rather than SHA-256, deliberately, and this is the one deviation this module makes from
 * "prefer the stronger primitive". RFC 6238 §1.2 permits SHA-1, SHA-256 and SHA-512, and the
 * `algorithm=` parameter of the otpauth:// URI exists to say which — but Google Authenticator and
 * several other widely deployed apps ignore that parameter and assume SHA-1 unconditionally. An
 * enrolment those apps silently compute the wrong codes for is a failed enrolment, and the person
 * cannot tell why. The choice costs nothing in strength: HMAC's security does not rest on the
 * collision resistance of its hash, which is the property SHA-1 lost.
 */

/* RFC 4226 §5.3 — HMAC over the 8-byte big-endian counter, dynamic truncation, decimal, zero-padded. */
export function hotp(
	secret: Buffer,
	counter: number,
	digits: number = DIGITS
): string {
	const message = Buffer.alloc(8);
	message.writeBigUInt64BE(BigInt(counter));

	const digest = crypto.createHmac('sha1', secret).update(message).digest();

	// The low four bits of the last byte choose where the four-byte window starts.
	const offset = digest[digest.length - 1] & 0x0f;
	const truncated =
		((digest[offset] & 0x7f) << 24) |
		((digest[offset + 1] & 0xff) << 16) |
		((digest[offset + 2] & 0xff) << 8) |
		(digest[offset + 3] & 0xff);

	return (truncated % 10 ** digits).toString().padStart(digits, '0');
}

/* RFC 6238 §4 — the counter for a moment in time. */
export function stepFor(unixSeconds: number): number {
	return Math.floor(unixSeconds / STEP_SECONDS);
}

function equals(a: string, b: string): boolean {
	const left = Buffer.from(a, 'ascii');
	const right = Buffer.from(b, 'ascii');
	// timingSafeEqual throws on a length mismatch, and a length difference is not secret anyway.
	if (left.length !== right.length) return false;
	return crypto.timingSafeEqual(left, right);
}

/*
 * Whether `code` is valid for `secret` at `unixSeconds`, within the drift band.
 *
 * Returns the **step it matched**, not a boolean, and that is load-bearing: the caller records it
 * against the account so the same code cannot be accepted twice while it is still nominally current
 * (lib/totp/verify.ts). A `verify(): boolean` shape cannot express that guard, and retrofitting it
 * would mean changing every call site.
 *
 * `after` refuses any step at or below it — the replay guard, expressed here so both the standing
 * enrolment and any future caller get it from one place.
 */
export function verifyAt(
	secret: Buffer,
	code: string,
	unixSeconds: number,
	opts: { after?: number; digits?: number; driftSteps?: number } = {}
): number | null {
	const digits = opts.digits ?? DIGITS;
	const drift = opts.driftSteps ?? DRIFT_STEPS;

	// Authenticator apps display `123 456`; the space is presentation, not input.
	const submitted = code.replace(/\s+/g, '');
	if (!new RegExp(`^[0-9]{${digits}}$`).test(submitted)) {
		return null;
	}

	const current = stepFor(unixSeconds);
	for (let step = current - drift; step <= current + drift; step += 1) {
		if (step < 0) continue;
		if (opts.after !== undefined && step <= opts.after) continue;
		if (equals(hotp(secret, step, digits), submitted)) {
			return step;
		}
	}

	return null;
}
