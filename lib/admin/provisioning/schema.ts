import { t } from 'elysia';

/*
 * Bodies of the provisioning-connection routes. Kept apart from the routes because lib/mcp/catalogue.ts
 * imports schema modules and must never import a route module (a route module reaches a database module
 * that connects at import time). Closed, so a field this server does not know is refused rather than
 * silently ignored — the same reason the client and resource bodies are.
 */

const Correlation = t.Object(
	{
		/* Checked against CLAIM_NAME_PATTERN by the service, which says why when it refuses. */
		claim: t.String({ minLength: 1, maxLength: 64 }),
		attribute: t.Union([t.Literal('externalId'), t.Literal('userName')])
	},
	{ additionalProperties: false }
);

const EmailTrust = t.Union([t.Literal('trusted'), t.Literal('untrusted')]);

export const CreateConnectionBody = t.Object(
	{
		displayName: t.String({ minLength: 1, maxLength: 100 }),
		providerId: t.String({ minLength: 1, maxLength: 32 }),
		correlation: t.Optional(Correlation),
		emailTrust: t.Optional(EmailTrust)
	},
	{ additionalProperties: false }
);

/* `providerId` is absent on purpose: re-binding a connection would re-key every user it provisioned. */
export const UpdateConnectionBody = t.Object(
	{
		displayName: t.Optional(t.String({ minLength: 1, maxLength: 100 })),
		enabled: t.Optional(t.Boolean()),
		correlation: t.Optional(Correlation),
		emailTrust: t.Optional(EmailTrust)
	},
	{ additionalProperties: false }
);

/*
 * One object rather than a union of three, because the MCP surface builds a tool's input from the body's
 * properties and a union has none to build from. The key fields mean something only with `kind: 'key'`;
 * the service refuses them otherwise, and says so.
 */
export const IssueCredentialBody = t.Object(
	{
		kind: t.Union([
			t.Literal('key'),
			t.Literal('secret'),
			t.Literal('static_token')
		]),
		jwks: t.Optional(
			t.Object({
				keys: t.Array(t.Record(t.String(), t.Unknown()), {
					minItems: 1,
					maxItems: 10
				})
			})
		),
		jwksUri: t.Optional(t.String({ maxLength: 2048 })),
		signingAlg: t.Optional(t.String({ maxLength: 16 }))
	},
	{ additionalProperties: false }
);

export const CredentialKindParam = t.Union([
	t.Literal('oauth'),
	t.Literal('static_token')
]);

/*
 * Handing a local user to a connection: the directory's names for them. At least one is required, which the
 * service checks so the refusal can say so in words.
 */
export const AssignConnectionBody = t.Object(
	{
		connectionId: t.String({ minLength: 1, maxLength: 64 }),
		userName: t.Optional(t.String({ minLength: 1, maxLength: 256 })),
		externalId: t.Optional(t.String({ minLength: 1, maxLength: 256 }))
	},
	{ additionalProperties: false }
);
