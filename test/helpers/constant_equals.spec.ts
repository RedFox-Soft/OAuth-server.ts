import constantEquals from '../../lib/helpers/constant_equals.ts';

describe('constantEquals', () => {
	it('compares strings in equal time', () => {
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

	it('also works when providing minComp', () => {
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
