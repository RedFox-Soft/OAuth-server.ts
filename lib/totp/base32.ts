/*
 * Base32 as RFC 4648 §6 defines it, unpadded.
 *
 * Unpadded because the only consumer is an `otpauth://` URI and a person retyping the secret from a
 * screen: every authenticator app accepts an unpadded secret, and a trailing run of '=' in a query
 * string is one more thing to percent-encode for no benefit. The decoder still accepts padding, so a
 * secret pasted from somewhere else is not refused for a difference that carries no information.
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function encodeBase32(bytes: Buffer): string {
	let out = '';
	let value = 0;
	let bits = 0;

	for (const byte of bytes) {
		value = (value << 8) | byte;
		bits += 8;
		while (bits >= 5) {
			out += ALPHABET[(value >>> (bits - 5)) & 31];
			bits -= 5;
		}
	}

	// The final partial group is left-aligned into five bits, which is what padding would have covered.
	if (bits > 0) {
		out += ALPHABET[(value << (5 - bits)) & 31];
	}

	return out;
}

export function decodeBase32(text: string): Buffer {
	// Whitespace and case are both artifacts of how the secret was shown, never of what it is: the
	// enrolment page prints it grouped in fours, and a person retyping it may lowercase it.
	const clean = text
		.replace(/[\s-]+/g, '')
		.replace(/=+$/, '')
		.toUpperCase();
	const out: number[] = [];
	let value = 0;
	let bits = 0;

	for (const character of clean) {
		const index = ALPHABET.indexOf(character);
		if (index === -1) {
			throw new TypeError(`not a base32 character: ${character}`);
		}
		value = (value << 5) | index;
		bits += 5;
		if (bits >= 8) {
			out.push((value >>> (bits - 8)) & 255);
			bits -= 8;
		}
	}

	return Buffer.from(out);
}
