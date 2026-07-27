import { addons } from '../lib/addon/registry.js';
import type { AddonImplementations } from '../lib/addon/types.js';

// Test-only bridge between a *.config.ts's `addons` named export and the addon
// override registry. A config declares the behaviour functions it overrides as a
// flat `export const addons = { getResourceServerInfo, ... }`; bootstrap() passes
// that object here as the spec's BASELINE.
//
// The global afterEach in preload.ts resets to this baseline after every test:
// per-test addons.override(...) calls are wiped (no cross-test leak), while the
// spec's config-declared overrides persist across the spec's tests. Each
// bootstrap() replaces the baseline, so overrides never leak across spec files.

let baseline: Partial<AddonImplementations> = {};

export function setAddonBaseline(
	overrides: Partial<AddonImplementations> | undefined
): void {
	baseline = { ...(overrides ?? {}) };
	addons.reset();
	addons.override(baseline);
}

export function resetToBaseline(): void {
	addons.reset();
	addons.override(baseline);
}
