import { t } from 'elysia';

import { NetworkFactsState } from '../settings/network_facts/schema.js';

/*
 * Looking an address up in this server's copy of FoxTrust's snapshot, for the console's "Check access" (specs/129
 * contracts/admin-and-proxy.md). The address travels in the body, never in a URL, so it reaches no access log. Its own
 * module because the MCP catalogue imports schema modules and never a route module.
 */
export const NetworkFactsLookupBody = t.Object(
	{ address: t.String({ minLength: 1, maxLength: 64 }) },
	{ additionalProperties: false }
);

export const NetworkFactsLookupResponse = t.Object({
	facts: t.Union([
		t.Object({
			known: t.Literal(true),
			categories: t.Array(
				t.Union([t.Literal('tor'), t.Literal('vpn'), t.Literal('hosting')])
			),
			country: t.Union([t.String(), t.Null()])
		}),
		t.Object({ known: t.Literal(false) })
	]),
	state: NetworkFactsState,
	fullVersion: t.Union([t.String(), t.Null()]),
	deltaVersion: t.Union([t.String(), t.Null()]),
	builtAt: t.Union([t.String(), t.Null()]),
	ageSeconds: t.Union([t.Number(), t.Null()])
});
