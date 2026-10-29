import { describe, expect, it } from 'bun:test';

import * as storedDocuments from 'lib/adapters/types.ts';
import * as clientSchemas from 'lib/configs/clientSchema.ts';
import * as federationSchemas from 'lib/federation/types.ts';
import * as totpSchemas from 'lib/totp/types.ts';
import { DECLARED_PLAINTEXT, SEALED_FIELDS } from 'lib/consts/sealed_fields.ts';

const SECRET_LOOKING = /secret|password|signingKey|salt/i;

type Schema = {
	type?: unknown;
	properties?: Record<string, Schema>;
	patternProperties?: Record<string, Schema>;
	items?: Schema | Schema[];
	anyOf?: Schema[];
	allOf?: Schema[];
};

function isSchema(value: unknown): value is Schema {
	return (
		typeof value === 'object' &&
		value !== null &&
		Symbol.for('TypeBox.Kind') in value
	);
}

function secretLookingNames(schema: Schema, found: Set<string>): void {
	for (const [name, member] of Object.entries(schema.properties ?? {})) {
		if (SECRET_LOOKING.test(name)) found.add(name);
		secretLookingNames(member, found);
	}
	for (const member of Object.values(schema.patternProperties ?? {})) {
		secretLookingNames(member, found);
	}
	const items = schema.items;
	for (const member of Array.isArray(items) ? items : items ? [items] : []) {
		secretLookingNames(member, found);
	}
	for (const member of [...(schema.anyOf ?? []), ...(schema.allOf ?? [])]) {
		secretLookingNames(member, found);
	}
}

/* The field name each declared leaf ends in: `federation[].clientSecret` is `clientSecret`. */
const sealedNames = new Set(
	SEALED_FIELDS.map((field) => field.path.split('.').pop() ?? '').filter(
		(name) => !name.startsWith('{')
	)
);
const plaintextNames = new Set(DECLARED_PLAINTEXT.map((entry) => entry.field));

/**
 * @proves No stored field that looks like a secret is left out of the decision: each is either sealed with the
 * keyring or stored as it is with a written reason, so a new secret cannot quietly be stored in plaintext.
 */
describe('the stored document schemas', () => {
	it('for every secret-named field in the storage inventory, the field is declared sealed or declared plaintext with a reason', () => {
		const found = new Set<string>();
		for (const module of [
			storedDocuments,
			clientSchemas,
			federationSchemas,
			totpSchemas
		]) {
			for (const value of Object.values(module)) {
				if (isSchema(value)) secretLookingNames(value, found);
			}
		}
		expect(found.size).toBeGreaterThan(0);
		const undecided = [...found].filter(
			(name) => !sealedNames.has(name) && !plaintextNames.has(name)
		);
		expect(undecided).toEqual([]);
		for (const entry of DECLARED_PLAINTEXT) {
			expect(entry.reason.trim().length, entry.field).toBeGreaterThan(0);
		}
	});
});
