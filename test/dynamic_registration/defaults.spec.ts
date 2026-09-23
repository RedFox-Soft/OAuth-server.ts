import { describe, beforeAll, it, expect } from 'bun:test';

import bootstrap, { agent } from '../test_helper.js';
import { ClientDefaults } from 'lib/configs/clientBase.js';
import { ATTRIBUTES } from 'lib/consts/client_attributes.ts';
import snakeCase from 'lib/helpers/_/snake_case.ts';
import { CLIENT_METADATA_WIRE_MAP } from 'lib/models/client/wire.ts';
import camelCase from 'lib/helpers/_/camel_case.ts';
import { ALWAYS_PRESENT } from 'lib/models/client/types.ts';

const json = { 'content-type': 'application/json' };
const REDIRECT = 'https://client.example.com/cb';

/* A base key has a wire name of its own; a recognised attribute's is its snake_case; a dotted base
 * key has none and is echoed as it is. */
function wireName(name: string): string {
	const mapped = Object.entries(CLIENT_METADATA_WIRE_MAP).find(
		([, canonical]) => canonical === name
	);
	if (mapped) return mapped[0];
	return name.includes('.') ? name : snakeCase(name);
}

/*
 * Every default that applies whatever the deployment has switched on, under the name a registering
 * client sees it by: the recognised attributes whose declaration gives a default and requires no
 * capability, and the base defaults. The redirect URIs are left out because a registration has to send
 * them. Keyed by the attribute's name on a validated client, which is what ALWAYS_PRESENT lists.
 */
function ungatedDefaults(): Map<string, unknown> {
	const recognised = Object.entries(ATTRIBUTES)
		.filter(
			([, rules]) => rules.default !== undefined && !rules.requires?.length
		)
		.map(([name, rules]): [string, unknown] => [
			camelCase(name),
			rules.default
		]);
	return new Map([...recognised, ...Object.entries(ClientDefaults)]);
}

/**
 * @proves A client that registers without an attribute the server always defaults is told the value
 * it was given, for every such attribute.
 */
describe('registering without the defaulted attributes', () => {
	beforeAll(async () => {
		await bootstrap(import.meta.url, { config: 'dynamic_registration' });
	});

	/*
	 * The type of a validated client marks ALWAYS_PRESENT as never absent. That holds only if the list
	 * is exactly the set of defaults applied whatever is switched on — one missing is an attribute the
	 * type would call optional, one extra an attribute it would promise and not deliver.
	 */
	it('marks as always present exactly the attributes that are defaulted regardless of capability', () => {
		expect([...ungatedDefaults().keys()].sort()).toEqual(
			[...ALWAYS_PRESENT].sort()
		);
	});

	it('echoes every default that applies regardless of capability', async () => {
		const defaults = [...ungatedDefaults()].filter(
			([name]) => name !== 'redirectUris'
		);
		expect(defaults.length).toBeGreaterThan(0);

		const { status, data } = await agent.reg.post(
			{ redirect_uris: [REDIRECT] },
			{ headers: json }
		);

		expect(status).toBe(201);
		const echoed = data as Record<string, unknown>;
		for (const [name, value] of defaults) {
			const wire = wireName(name);
			expect({ [wire]: echoed[wire] }).toEqual({ [wire]: value });
		}
	});
});
