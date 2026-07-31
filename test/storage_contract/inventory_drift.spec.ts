import { describe, it, expect } from 'bun:test';
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import {
	FIXED_AREAS,
	MODEL_AREAS,
	STORAGE_INVENTORY,
	STORE_AREAS
} from 'lib/consts/storage_inventory.js';

// The two-way drift guard over the provisioning inventory — the storage counterpart of
// test/feature_gate/route_classification.spec.ts.
//
// The failure this exists to prevent is an area the server writes to that `bun run db:setup` never
// provisions: it auto-creates on first write with no indexes, so nothing reaps it and nothing
// constrains it. That is how VerificationChallenge, VerificationResend and serviceConfig came to be
// missing, and it is invisible until production storage misbehaves.
//
// Both halves derive the "used" set from something a developer cannot bypass while still adding
// working storage. A hand-written list would not: whoever forgets the inventory forgets the list too.
// Nothing here touches a database — lib/consts/storage_inventory.ts imports nothing, which is what
// makes production-storage drift checkable against the in-memory adapter.

const LIB = resolve(import.meta.dir, '../../lib');
const MODELS = join(LIB, 'models');

function libSources(): string[] {
	return readdirSync(LIB, { recursive: true, encoding: 'utf8' })
		.filter((entry) => entry.endsWith('.ts'))
		.map((entry) => join(LIB, entry));
}

// Collection names passed to `adapter()` as a literal. Sees only literal arguments by construction;
// the one dynamic form in the codebase is `adapter(this.name)` on the model classes, which the
// second half below covers.
function literalAdapterAreas(): Map<string, string> {
	const found = new Map<string, string>();
	for (const file of libSources()) {
		const source = readFileSync(file, 'utf8');
		for (const match of source.matchAll(/\badapter\(\s*'([^']+)'\s*\)/g)) {
			const area = match[1];
			if (area !== undefined && !found.has(area)) {
				found.set(area, file);
			}
		}
	}
	return found;
}

interface DiscoveredClass {
	readonly name: string;
	readonly ctor: Function;
	readonly file: string;
}

// Every exported class in lib/models/*.ts that reaches BaseModel's `static get adapter()`, which
// resolves its collection as `adapter(this.name)` — so for these classes the class name *is* the
// area name.
async function modelClasses(): Promise<DiscoveredClass[]> {
	const files = readdirSync(MODELS)
		.filter((entry) => entry.endsWith('.ts'))
		.map((entry) => join(MODELS, entry));

	const discovered: DiscoveredClass[] = [];
	for (const file of files) {
		// Annotated rather than asserted: a dynamic import of a runtime-computed path is typed `any`,
		// which the annotation accepts directly.
		const module: Record<string, unknown> = await import(
			pathToFileURL(file).href
		);
		for (const exported of Object.values(module)) {
			if (typeof exported !== 'function' || !hasStaticAdapter(exported)) {
				continue;
			}
			discovered.push({ name: exported.name, ctor: exported, file });
		}
	}
	return discovered;
}

// Reads the descriptor without invoking the getter, so no adapter is instantiated by this spec.
function hasStaticAdapter(candidate: Function): boolean {
	let current: unknown = candidate;
	while (typeof current === 'function') {
		const descriptor = Object.getOwnPropertyDescriptor(current, 'adapter');
		if (descriptor && typeof descriptor.get === 'function') {
			return true;
		}
		current = Object.getPrototypeOf(current);
	}
	return false;
}

// BaseModel and BaseToken carry the accessor but are not themselves persisted. They are excluded
// structurally rather than by name: a base class appears in some other discovered class's prototype
// chain, and no persisted model extends another persisted model. Adding a third base class therefore
// needs no edit here, and a persisted model that accidentally extends another would fail loudly
// rather than slip through.
function persistedModelClasses(all: DiscoveredClass[]): DiscoveredClass[] {
	const bases = new Set<Function>();
	for (const { ctor } of all) {
		let parent: unknown = Object.getPrototypeOf(ctor);
		while (typeof parent === 'function') {
			bases.add(parent);
			parent = Object.getPrototypeOf(parent);
		}
	}
	return all.filter(({ ctor }) => !bases.has(ctor));
}

describe('storage inventory drift', () => {
	const inventoried = new Set<string>(MODEL_AREAS);

	it('inventories every area reached by a literal adapter() call', () => {
		const uninventoried = [...literalAdapterAreas()]
			.filter(([area]) => !inventoried.has(area))
			.map(([area, file]) => `${area} (${file})`);

		expect(uninventoried).toEqual([]);
	});

	it('inventories every persisted model class in lib/models', async () => {
		const uninventoried = persistedModelClasses(await modelClasses())
			.filter(({ name }) => !inventoried.has(name))
			.map(({ name, file }) => `${name} (${file})`);

		expect(uninventoried).toEqual([]);
	});

	// The reverse direction, and the half that rots silently: an inventory entry for a model the
	// server no longer has costs an empty collection and a false sense of coverage.
	it('declares no model area the server does not use', async () => {
		const used = new Set<string>(literalAdapterAreas().keys());
		for (const { name } of persistedModelClasses(await modelClasses())) {
			used.add(name);
		}

		const stale = MODEL_AREAS.filter((area) => !used.has(area));

		expect(stale).toEqual([]);
	});

	// Guards the discriminator itself. If a refactor made every class in lib/models look like a base
	// (or none), the two checks above would pass while testing nothing.
	it('discovers the model classes it claims to', async () => {
		const persisted = persistedModelClasses(await modelClasses()).map(
			(c) => c.name
		);

		expect(persisted.length).toBeGreaterThan(10);
		expect(persisted).toContain('Session');
		expect(persisted).toContain('AccessToken');
		// The accessor's definition sites, excluded structurally.
		expect(persisted).not.toContain('BaseModel');
		expect(persisted).not.toContain('BaseToken');
		// Not persisted: IdToken is signed and returned, never stored.
		expect(persisted).not.toContain('IdToken');
	});

	it('names each storage area exactly once', () => {
		const names = STORAGE_INVENTORY.map((area) => area.name);

		expect(names.length).toBe(new Set(names).size);
	});

	it('provisions every dedicated-store area', () => {
		const inventoriedNames = new Set(FIXED_AREAS.map((area) => area.name));
		const storeNames = Object.values(STORE_AREAS);

		const missing = storeNames.filter((name) => !inventoriedNames.has(name));

		expect(missing).toEqual([]);
		expect(storeNames.length).toBe(new Set(storeNames).size);
	});

	// Exactly one templated entry, because the routine resolves per-bucket provisioning through it.
	it('declares a single per-bucket area template', () => {
		const perBucket = STORAGE_INVENTORY.filter(
			(area) => area.kind === 'perBucket'
		);

		expect(perBucket.length).toBe(1);
		expect(FIXED_AREAS.length).toBe(STORAGE_INVENTORY.length - 1);
	});
});
