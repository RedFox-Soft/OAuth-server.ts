import { describe, it, expect } from 'bun:test';

import { canonicalKey, canonicalKeySet } from 'lib/helpers/rar_canonical.js';

describe('rar canonical key', () => {
	it('is insensitive to member order', () => {
		expect(canonicalKey({ type: 'a', actions: ['read'] })).toBe(
			canonicalKey({ actions: ['read'], type: 'a' })
		);
	});

	it('is insensitive to member order at any depth', () => {
		expect(canonicalKey({ type: 'a', meta: { x: 1, y: 2 } })).toBe(
			canonicalKey({ meta: { y: 2, x: 1 }, type: 'a' })
		);
	});

	/*
	 * §12 forbids normalizing string values, so these are DIFFERENT details. A helper that trimmed or
	 * case-folded would silently merge two distinct authorizations.
	 */
	it('is sensitive to case in string values', () => {
		expect(canonicalKey({ type: 'a', actions: ['Read'] })).not.toBe(
			canonicalKey({ type: 'a', actions: ['read'] })
		);
	});

	it('is sensitive to surrounding whitespace in string values', () => {
		expect(canonicalKey({ type: 'a', identifier: ' 1 ' })).not.toBe(
			canonicalKey({ type: 'a', identifier: '1' })
		);
	});

	it('treats array element order as significant', () => {
		expect(canonicalKey({ type: 'a', actions: ['read', 'write'] })).not.toBe(
			canonicalKey({ type: 'a', actions: ['write', 'read'] })
		);
	});

	it('handles non-object input without throwing', () => {
		expect(canonicalKey(undefined)).toBe('undefined');
		expect(canonicalKey(null)).toBe('null');
		expect(canonicalKey('a')).toBe('"a"');
	});

	it('builds a set only from arrays', () => {
		expect(canonicalKeySet([{ type: 'a' }, { type: 'a' }]).size).toBe(1);
		expect(canonicalKeySet(undefined).size).toBe(0);
		expect(canonicalKeySet({ type: 'a' }).size).toBe(0);
	});
});
