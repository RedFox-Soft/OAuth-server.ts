import { describe, it, expect } from 'bun:test';
import { merge } from 'lib/helpers/_/object.js';

describe('merge', () => {
	it('merges objects', () => {
		const target = { a: 1, b: 2, c: { d: 3 } };
		merge(target, { a: 'x', b: { b: 2 }, c: { e: 4 } }, { c: { f: 5 } });
		expect(target).toEqual({ a: 'x', b: { b: 2 }, c: { d: 3, e: 4, f: 5 } });
	});
});
