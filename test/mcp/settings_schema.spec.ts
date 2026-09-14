import { describe, it, expect } from 'bun:test';

import {
	SETTINGS_CATALOG,
	type SettingType
} from 'lib/admin/settings/catalog.ts';
import { mcpCatalogue } from 'lib/mcp/catalogue.ts';
import { inputSchemaFor } from 'lib/mcp/server.ts';

/*
 * `settings_update` published its body as an open map with no properties at all, because the route's
 * own body is a partial map of setting key to value that validates nothing. An agent reading that
 * schema is told nothing about any setting, so a client with no type to check a value against sends
 * the text it was given: `par.enabled: true` arrives as `"true"` and the route refuses it as not a
 * boolean. Two clients were observed doing it, which is what rules out blaming either one.
 *
 * There is no encoding that works around it from the caller's side — the route wants flat dotted keys
 * carrying real booleans and arrays — so the schema has to say what each setting takes.
 */

/* What each catalog type must reach an agent as. */
const PUBLISHED_TYPE: Record<SettingType, string> = {
	boolean: 'boolean',
	string: 'string',
	number: 'number',
	enum: 'string',
	'string-array': 'array',
	json: 'object'
};

const settingsUpdate = mcpCatalogue.find((t) => t.tool === 'settings_update');
if (!settingsUpdate) throw new Error('settings_update is not published');

const published = inputSchemaFor(settingsUpdate);
const properties = published.properties as Record<
	string,
	{ type?: string; items?: { type?: string } } | undefined
>;

/**
 * @proves An agent is told what every editable setting accepts, so it sends a typed value rather
 * than the text of one, and a setting nobody declared is still refused by name.
 */
describe('the published schema of the settings tool', () => {
	it('declares the type of every editable setting', () => {
		const undeclared = SETTINGS_CATALOG.filter(
			(d) => properties[d.key as string]?.type !== PUBLISHED_TYPE[d.type]
		).map(
			(d) =>
				`${d.key}: expected ${PUBLISHED_TYPE[d.type]}, published ${
					properties[d.key as string]?.type ?? 'nothing'
				}`
		);

		expect(undeclared).toBeArrayOfSize(0);
	});

	// The second symptom, and a distinct defect: `type: 'array'` alone still leaves a client guessing
	// what goes in it, and `scopes` arrived as one string rather than as a list.
	it('declares what a list setting holds', () => {
		const listKeys = SETTINGS_CATALOG.filter((d) => d.type === 'string-array');
		expect(listKeys.length).toBeGreaterThan(0);

		const vague = listKeys
			.filter((d) => properties[d.key as string]?.items?.type !== 'string')
			.map((d) => d.key as string);

		expect(vague).toBeArrayOfSize(0);
	});

	/*
	 * Declaring the catalog must not close the object. A key the catalog does not know has to reach the
	 * handler to be refused as `unknown setting: <key>`; refused by the tool schema instead, an agent is
	 * told only that an argument was rejected, and a setting retired between releases becomes a silent
	 * drop rather than a message naming it.
	 */
	it('still carries a setting it does not declare, so an unknown one is refused by name', () => {
		expect(published.additionalProperties).toBe(true);
	});
});
