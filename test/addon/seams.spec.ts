import { describe, it, expect } from 'bun:test';

// Warm the model graph before the addon index: a cold entry through lib/addon/index.ts reaches
// lib/models/ and throws a TDZ ReferenceError (wiki/concepts/model-graph-import-order.md).
import { elysia } from '../../lib/index.ts';
import * as addonIndex from 'lib/addon/index.ts';
import { ADDON_SEAMS } from 'lib/addon/seams.ts';

void elysia;

/*
 * The documentation export lists the seams from ADDON_SEAMS, and the index is what a deployment
 * actually overrides. The two are held equal here because the type-level check in seams.ts catches a
 * seam missing from the list but cannot catch an accessor removed from the index while its type
 * lingers in AddonImplementations.
 */
describe('addon seams', () => {
	// Exported from the index but not seams: the registry itself, the warn helpers, and the two
	// interaction-policy controls that already read through the registry internally.
	const NOT_SEAMS = new Set([
		'addons',
		'shouldChange',
		'mustChange',
		'interactionPolicyControl',
		'supportedPrompts'
	]);

	it('lists exactly the overridable functions the addon index exposes', () => {
		const exported = Object.entries(addonIndex)
			.filter(
				([name, value]) => typeof value === 'function' && !NOT_SEAMS.has(name)
			)
			.map(([name]) => name)
			.sort();

		expect(([...ADDON_SEAMS] as string[]).sort()).toEqual(exported);
	});

	it('names each seam once', () => {
		expect(new Set(ADDON_SEAMS).size).toBe(ADDON_SEAMS.length);
	});
});
