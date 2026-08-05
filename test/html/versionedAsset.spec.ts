import { describe, it, expect } from 'bun:test';

import { versionedAsset } from 'lib/html/versionedAsset.js';

describe('versionedAsset', () => {
	it('addresses an existing asset by its build time', () => {
		// Checked in, so it is present in every checkout and in CI.
		const address = versionedAsset('logo.svg');
		expect(address).toStartWith('/public/logo.svg?v=');
		expect(address.split('?v=')[1]).toMatch(/^[0-9a-z]+$/);
	});

	/*
	 * The absent case is the normal one for a built bundle in a fresh checkout: the server and the test
	 * suite both run before `bun run build`. An unversioned address still resolves, where a bare `?v=`
	 * would be a cache key of its own.
	 */
	it('leaves an unbuilt asset unversioned rather than emitting an empty version', () => {
		expect(versionedAsset('nothing-built-yet.css')).toBe(
			'/public/nothing-built-yet.css'
		);
	});

	it('is stable across calls for an unchanged file', () => {
		expect(versionedAsset('logo.svg')).toBe(versionedAsset('logo.svg'));
	});
});
