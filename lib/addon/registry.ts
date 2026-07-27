import type { AddonImplementations } from './types.js';

// The mutable override map. Empty means "use the addon-module default". Kept in a
// module that imports no runtime code so it can be imported anywhere — including
// the test preload — without loading the addon modules (and their model graph).
const overrides: Partial<AddonImplementations> = {};

// The override seam. Deployments and tests replace behavior here; source modules
// never read these functions off the merged configuration. A single global
// afterEach in test/preload.ts calls reset() so suites stay isolated.
export const addons = {
	override(partial: Partial<AddonImplementations>): void {
		Object.assign(overrides, partial);
	},
	reset(): void {
		for (const key of Object.keys(
			overrides
		) as (keyof AddonImplementations)[]) {
			delete overrides[key];
		}
	}
};

// Resolve the active implementation for a key at call time: the registered
// override if present, otherwise the addon-module default passed by the accessor.
export function resolve<K extends keyof AddonImplementations>(
	key: K,
	fallback: AddonImplementations[K]
): AddonImplementations[K] {
	return overrides[key] ?? fallback;
}
