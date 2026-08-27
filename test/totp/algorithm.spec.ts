import { describe, it, expect } from 'bun:test';
import { encodeBase32, decodeBase32 } from 'lib/totp/base32.ts';
import { hotp, stepFor, verifyAt } from 'lib/totp/code.ts';
import { STEP_SECONDS } from 'lib/totp/consts.ts';

// The secret every published vector uses: the ASCII digits 1-0 repeated to 20 bytes.
const SEED = Buffer.from('12345678901234567890', 'ascii');

describe('base32 (RFC 4648 §6)', () => {
	// RFC 4648 §10 test vectors, unpadded — the padding this codec omits is the '=' run at the end.
	const vectors: [string, string][] = [
		['', ''],
		['f', 'MY'],
		['fo', 'MZXQ'],
		['foo', 'MZXW6'],
		['foob', 'MZXW6YQ'],
		['fooba', 'MZXW6YTB'],
		['foobar', 'MZXW6YTBOI']
	];

	for (const [plain, encoded] of vectors) {
		it(`encodes ${JSON.stringify(plain)} as ${JSON.stringify(encoded)}`, () => {
			expect(encodeBase32(Buffer.from(plain, 'ascii'))).toBe(encoded);
		});

		it(`decodes ${JSON.stringify(encoded)} back to ${JSON.stringify(plain)}`, () => {
			expect(decodeBase32(encoded).toString('ascii')).toBe(plain);
		});
	}

	it('round-trips the 20-byte seed', () => {
		expect(decodeBase32(encodeBase32(SEED)).equals(SEED)).toBe(true);
	});

	// A person retyping a secret off a screen produces both of these.
	it('tolerates lowercase and embedded spaces on decode', () => {
		const encoded = encodeBase32(SEED);
		const grouped = (encoded.match(/.{1,4}/g) ?? []).join(' ').toLowerCase();
		expect(decodeBase32(grouped).equals(SEED)).toBe(true);
	});

	it('refuses a character outside the alphabet', () => {
		expect(() => decodeBase32('MZXW6YTB!')).toThrow();
	});
});

describe('hotp (RFC 4226 Appendix D)', () => {
	const expected = [
		'755224',
		'287082',
		'359152',
		'969429',
		'338314',
		'254676',
		'287922',
		'162583',
		'399871',
		'520489'
	];

	expected.forEach((code, counter) => {
		it(`counter ${counter} yields ${code}`, () => {
			expect(hotp(SEED, counter)).toBe(code);
		});
	});
});

describe('totp (RFC 6238 Appendix B)', () => {
	// The SHA-1 column. Eight digits, which is what the appendix tabulates.
	const vectors: [number, string][] = [
		[59, '94287082'],
		[1111111109, '07081804'],
		[1111111111, '14050471'],
		[1234567890, '89005924'],
		[2000000000, '69279037'],
		[20000000000, '65353130']
	];

	for (const [time, code] of vectors) {
		it(`T=${time} yields ${code}`, () => {
			expect(hotp(SEED, stepFor(time), 8)).toBe(code);
		});
	}

	it('derives the step by flooring the unix time over the period', () => {
		expect(stepFor(0)).toBe(0);
		expect(stepFor(STEP_SECONDS - 1)).toBe(0);
		expect(stepFor(STEP_SECONDS)).toBe(1);
		expect(stepFor(59)).toBe(1);
	});
});

describe('verifyAt', () => {
	const NOW = 1234567890;
	const step = stepFor(NOW);

	it('accepts the current step and returns it', () => {
		expect(verifyAt(SEED, hotp(SEED, step), NOW)).toBe(step);
	});

	it('accepts the step before and the step after', () => {
		expect(verifyAt(SEED, hotp(SEED, step - 1), NOW)).toBe(step - 1);
		expect(verifyAt(SEED, hotp(SEED, step + 1), NOW)).toBe(step + 1);
	});

	it('refuses two steps out in either direction', () => {
		expect(verifyAt(SEED, hotp(SEED, step - 2), NOW)).toBeNull();
		expect(verifyAt(SEED, hotp(SEED, step + 2), NOW)).toBeNull();
	});

	it('refuses a code that is not a code at all', () => {
		expect(verifyAt(SEED, '000000', NOW)).toBeNull();
		expect(verifyAt(SEED, '', NOW)).toBeNull();
		expect(verifyAt(SEED, 'abcdef', NOW)).toBeNull();
	});

	// The replay guard: a step at or below `after` is spent, even though it is still within the band.
	it('refuses a step at or below `after`', () => {
		expect(verifyAt(SEED, hotp(SEED, step), NOW, { after: step })).toBeNull();
		expect(
			verifyAt(SEED, hotp(SEED, step - 1), NOW, { after: step })
		).toBeNull();
	});

	it('still accepts the next step once `after` is set', () => {
		expect(verifyAt(SEED, hotp(SEED, step + 1), NOW, { after: step })).toBe(
			step + 1
		);
	});
});
