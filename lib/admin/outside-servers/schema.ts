import { t } from 'elysia';

/*
 * Bodies of the outside-authorization-server routes (specs/108). Kept apart from the routes because
 * lib/mcp/catalogue.ts imports schema modules and must never import a route module. Closed, so a field this
 * server does not know is refused rather than silently ignored.
 *
 * Shapes only: whether an issuer is safe to vouch to, an application may ask, a group exists, are rules the
 * service decides and explains, so each refusal has one definition reachable from the console and an agent.
 * Edge words — `applications`, `apis`, `groups`, `signInApplication` — are translated to the stored ones by
 * the service's explicit projection, never by renaming keys wholesale.
 */

const Application = t.Object(
	{
		clientId: t.String({ minLength: 1, maxLength: 2048 }),
		/* The application's client id at the outside server; required unless its own id is a URL (ID-JAG §5). */
		externalClientId: t.Optional(t.String({ minLength: 1, maxLength: 512 }))
	},
	{ additionalProperties: false }
);

const Api = t.Object(
	{
		identifier: t.String({ minLength: 1, maxLength: 2048 }),
		scopes: t.Array(t.String({ minLength: 1, maxLength: 200 }), {
			maxItems: 50
		})
	},
	{ additionalProperties: false }
);

const Audience = t.Union([
	t.Literal('everyone'),
	t.Object(
		{
			groups: t.Array(t.String({ minLength: 1, maxLength: 64 }), {
				maxItems: 50
			})
		},
		{ additionalProperties: false }
	)
]);

const Rule = t.Object(
	{
		appliesTo: Audience,
		apis: t.Array(Api, { maxItems: 50 })
	},
	{ additionalProperties: false }
);

const DisplayName = t.String({ minLength: 1, maxLength: 100 });
const Applications = t.Array(Application, { maxItems: 50 });
const Rules = t.Array(Rule, { maxItems: 50 });

export const CreateOutsideServerBody = t.Object(
	{
		issuer: t.String({ minLength: 1, maxLength: 2048 }),
		displayName: DisplayName,
		applications: Applications,
		rules: Rules,
		signInApplication: t.Optional(t.String({ minLength: 1, maxLength: 2048 })),
		includeEmail: t.Optional(t.Boolean())
	},
	{ additionalProperties: false }
);

/*
 * `issuer` is accepted only to be refused when it differs: what a project vouched to one server must not be
 * silently redirected to another, so connecting another server is a new connection. `signInApplication: null`
 * removes it.
 */
export const UpdateOutsideServerBody = t.Object(
	{
		issuer: t.Optional(t.String({ minLength: 1, maxLength: 2048 })),
		displayName: t.Optional(DisplayName),
		applications: t.Optional(Applications),
		rules: t.Optional(Rules),
		signInApplication: t.Optional(
			t.Union([t.String({ minLength: 1, maxLength: 2048 }), t.Null()])
		),
		includeEmail: t.Optional(t.Boolean())
	},
	{ additionalProperties: false }
);
