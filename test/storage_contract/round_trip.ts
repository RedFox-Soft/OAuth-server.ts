import { expect } from 'bun:test';

import { TestAdapter } from 'test/models.js';

// Schema-driven storage round-trip assertions — Contract B in
// specs/009-uniform-storage-filter/contracts/storage-contract.md.
//
// The TypeBox schema declared on the model instance (`instance.model`) is the SINGLE SOURCE OF
// TRUTH for the persisted key set. Expectations are derived from `instance.model.properties`; the
// harness never captures an unfiltered runtime snapshot to build the expected key list.

type Persisted = Record<string, unknown>;

interface PersistedModel {
	id: string;
	payload: Record<string, unknown>;
	model: { properties: Record<string, unknown> };
	constructor: { name: string };
}

// The raw payload the adapter received for `instance` (post-filter), read from the model's own
// namespace — the same name save() upserts under.
export function storedPayloadFor(
	instance: PersistedModel
): Persisted | undefined {
	return TestAdapter.for(instance.constructor.name).syncFind(instance.id) as
		Persisted | undefined;
}

// Asserts an already-saved instance honors the schema-driven storage contract:
//   no-leak — every persisted key is declared in the schema (⊆ model.properties)
//   no-loss — every schema field defined on the payload is persisted verbatim (shallow deep-equal)
// Returns the stored payload for any model-specific follow-up assertions.
export function assertStoredMatchesSchema(instance: PersistedModel): Persisted {
	const name = instance.constructor.name;
	const schemaKeys = Object.keys(instance.model.properties);
	const stored = storedPayloadFor(instance);

	if (!stored) {
		throw new Error(
			`${name} was not persisted (no stored payload for id ${instance.id})`
		);
	}

	// no-leak: the adapter must never receive a field the schema does not declare.
	for (const key of Object.keys(stored)) {
		expect(
			schemaKeys,
			`persisted key "${key}" is not declared in the ${name} schema`
		).toContain(key);
	}

	// no-loss (verbatim, shallow): every defined schema field on the payload survives deep-equal.
	// Freeform sub-objects are compared verbatim because the projection is a shallow top-level copy.
	for (const key of schemaKeys) {
		const value = instance.payload[key];
		if (value === undefined) continue;
		expect(
			stored,
			`persisted ${name} payload is missing schema field "${key}"`
		).toHaveProperty(key);
		expect(
			stored[key],
			`persisted ${name}.${key} is not stored verbatim`
		).toEqual(value);
	}

	return stored;
}

// Asserts none of `keys` (transient / instance-only fields) leaked into storage.
export function assertNotPersisted(
	instance: PersistedModel,
	keys: string[]
): void {
	const stored = storedPayloadFor(instance);
	if (!stored) {
		throw new Error(`${instance.constructor.name} was not persisted`);
	}
	for (const key of keys) {
		expect(
			stored,
			`transient field "${key}" must not be persisted for ${instance.constructor.name}`
		).not.toHaveProperty(key);
	}
}
