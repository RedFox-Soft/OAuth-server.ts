import { describe, it, expect } from 'bun:test';
import constantEquals from '../../lib/helpers/constant_equals.ts';

/*
 * These two cases prove the comparison's RESULTS, not its timing. The name they used to carry -
 * "compares strings in equal time" - claimed a property neither of them measures, which is why
 * nobody noticed the timing invariant has never been tested. Recorded as G-001 in Task.md; the
 * timing assertion is new coverage and belongs in its own change.
 */
/**
 * @proves Secret comparison answers equal only for identical secrets, whatever their lengths and
 * whatever comparison length is forced.
 */
describe('secret comparison', () => {
	it('answers equal only for identical secrets, whatever their lengths', () => {
		const a = 'abcdf';
		const b = 'abcdf';
		const c = 'abcde';
		const d = 'abcdef';

		expect(constantEquals(a, b)).toBe(true);
		expect(constantEquals(b, c)).toBe(false);
		expect(constantEquals(c, d)).toBe(false);
		expect(constantEquals(a, a)).toBe(true);
		expect(constantEquals('abc', 'a0c')).toBe(false);
		expect(() => constantEquals(Buffer.alloc(1), 'abc')).toThrow();
	});

	it('answers the same when a comparison length is forced, however it is padded', () => {
		const a1 = 'abcde';
		const a2 = 'abcde';
		const b1 = 'abcdef';
		const c1 = 'abcdeg';

		expect(constantEquals(a1, a2, 0)).toBe(true);
		expect(constantEquals(a1, a2, a1.length)).toBe(true);
		expect(constantEquals(a1, a2, a1.length + 1)).toBe(true);

		expect(constantEquals(a1, b1, 0)).toBe(false);
		expect(constantEquals(a1, b1, a1.length)).toBe(false);
		expect(constantEquals(a1, b1, a1.length + 1)).toBe(false);

		expect(constantEquals(b1, c1, 0)).toBe(false);
		expect(constantEquals(b1, c1, b1.length - 1)).toBe(false);
		expect(constantEquals(b1, c1, b1.length)).toBe(false);
		expect(constantEquals(b1, c1, b1.length + 1)).toBe(false);
		expect(() => constantEquals(Buffer.alloc(1), c1, c1.length + 1)).toThrow();

		expect(constantEquals('foo', 'foo', 512)).toBe(true);
	});
});
