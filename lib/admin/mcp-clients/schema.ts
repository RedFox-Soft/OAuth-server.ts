import { t } from 'elysia';

/*
 * Bodies for the administrative client permission routes.
 *
 * In a schema module rather than inline for the same reason every other group's are: `lib/mcp/
 * catalogue.ts` imports schema modules and must never import a route module. These particular
 * operations are withheld from the agent surface, so the catalogue never reads these — but the import
 * rule is about what a module *may* reach, not about who happens to read it today, and an exception
 * here would be the one someone copies.
 */
export const PermitMcpClientBody = t.Object(
	{
		kind: t.Union([t.Literal('identifier'), t.Literal('host')]),
		value: t.String({ minLength: 1 }),
		requireKeyProof: t.Optional(t.Boolean()),
		/*
		 * Required — and refused without — when the document behind `value` offers only loopback
		 * redirect targets. Not a checkbox the route ignores: such a document proves control of a domain
		 * but cannot prove which local process will receive the authorization code, and the
		 * administrator granting administrative authority on that basis has to say they were told.
		 */
		acknowledgeLoopbackRisk: t.Optional(t.Boolean())
	},
	{ additionalProperties: false }
);

export const UpdateMcpClientBody = t.Object(
	{
		requireKeyProof: t.Boolean()
	},
	{ additionalProperties: false }
);
