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
import { grantable } from 'lib/adapters/memory/helpers.js';
import {
	OWNER_FIELDS,
	PAYLOAD_SCHEMAS,
	SCHEMA_EXEMPT_AREAS
} from './payload_schemas.js';

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

// The ownership half of the guard — specs/019-deletion-integrity/contracts/cascade-engine.md, G1..G7.
//
// The failure this exists to prevent is a storage area the server writes to that no deletion cascade
// ever visits: its records outlive the principal they belong to, and nothing says so. A hand-written
// cascade per entity fails exactly this way, silently, the first time an area is added — which is why
// ownership is declared as data and read from one place.
//
// Fields are compared against each area's TypeBox schema properties, never against its source text:
// lib/models/session.ts declares `clientId` inside its nested `authorizations` object, so a text scan
// reports Session as client-owned when its top-level payload has no such field.

const IDENTIFIER = /^[A-Za-z][A-Za-z0-9_]*$/;

describe('storage ownership drift', () => {
	it('declares ownership for every storage area', () => {
		const undeclared = STORAGE_INVENTORY.filter((area) => !area.owners).map(
			(area) => area.name
		);

		expect(undeclared).toEqual([]);
	});

	// `reason` is required exactly when nothing is owned, so "no owner" is always a decision someone
	// wrote down rather than a field left blank — the same rule `reaped: null` already follows.
	it('states a reason exactly when an area owns nothing', () => {
		const wrong = STORAGE_INVENTORY.filter((area) => {
			const owned = area.owners.account !== null || area.owners.client !== null;
			const reasoned = (area.owners.reason ?? '').trim().length > 0;
			return owned === reasoned;
		}).map((area) => area.name);

		expect(wrong).toEqual([]);
	});

	// Field names reach MongoDB as `payload.<field>`. Constraining them to plain identifiers is what
	// makes it structurally impossible for a `$`-prefixed or dotted value to be interpreted as an
	// operator or a path.
	it('declares only plain identifiers as owner field names', () => {
		const malformed = STORAGE_INVENTORY.flatMap((area) =>
			[area.owners.account, area.owners.client]
				.filter((field): field is string => field !== null)
				.filter((field) => !IDENTIFIER.test(field))
				.map((field) => `${area.name}.${field}`)
		);

		expect(malformed).toEqual([]);
	});

	it('declares only fields the area payload schema carries', () => {
		const missing = STORAGE_INVENTORY.flatMap((area) => {
			const schema = PAYLOAD_SCHEMAS[area.name];
			if (!schema) return [];
			return [area.owners.account, area.owners.client]
				.filter((field): field is string => field !== null)
				.filter((field) => !(field in schema.properties))
				.map((field) => `${area.name}.${field}`);
		});

		expect(missing).toEqual([]);
	});

	// The reverse direction, and the half that rots silently: a payload that gained an owner field the
	// table does not declare is an owned record no cascade sweeps.
	it('declares every owner field the payload schemas carry', () => {
		const undeclared = STORAGE_INVENTORY.flatMap((area) => {
			const schema = PAYLOAD_SCHEMAS[area.name];
			if (!schema || SCHEMA_EXEMPT_AREAS.has(area.name)) return [];
			return OWNER_FIELDS.filter(
				(field) =>
					field in schema.properties &&
					area.owners.account !== field &&
					area.owners.client !== field
			).map((field) => `${area.name}.${field}`);
		});

		expect(undeclared).toEqual([]);
	});

	// Guards the two checks above: without this, an area with no registered schema silently skips both.
	it('registers a payload schema for every model area but the exempt ones', () => {
		const unregistered = MODEL_AREAS.filter(
			(area) => !SCHEMA_EXEMPT_AREAS.has(area) && !(area in PAYLOAD_SCHEMAS)
		);
		const stale = Object.keys(PAYLOAD_SCHEMAS).filter(
			(area) => !MODEL_AREAS.includes(area as (typeof MODEL_AREAS)[number])
		);

		expect(unregistered).toEqual([]);
		expect(stale).toEqual([]);
	});

	// The cascade engine resolves a sweep through `adapter()`, which only serves model areas, so it
	// filters to those. This is what stops that filter from ever quietly dropping an owned area.
	it('declares owners only on model areas', () => {
		const misplaced = STORAGE_INVENTORY.filter(
			(area) =>
				area.kind !== 'model' &&
				(area.owners.account !== null || area.owners.client !== null)
		).map((area) => `${area.name} (${area.kind})`);

		expect(misplaced).toEqual([]);
	});

	// `grantable` decides which areas the in-memory adapter indexes under `grant:<id>`, and the
	// `payload.grantId` index specs decide which areas MongoDB can revoke by grant. Two enumerations of
	// one fact; this keeps them equal. (revoke() is the third — single-sourcing all three means deriving
	// an index from a declaration, deferred deliberately: see research D8.)
	it('keeps the memory grant index aligned with the grant-indexed areas', () => {
		const grantIndexed = STORAGE_INVENTORY.filter((area) =>
			area.indexes.some((index) => 'payload.grantId' in index.key)
		).map((area) => area.name);

		expect([...grantable].sort()).toEqual(grantIndexed.sort());
	});
});
