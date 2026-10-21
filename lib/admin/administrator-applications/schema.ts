import { t } from 'elysia';

/*
 * Bodies of the routes for applications in the administrators' project (specs/109). Kept apart from the
 * routes because lib/mcp/catalogue.ts imports schema modules and must never import a route module.
 *
 * Closed, and deliberately narrow: such an application only ever signs an administrator in, so nothing here
 * can name a grant, a response type, a resource or a project — a member this server does not know is refused,
 * not ignored. What remains is what an internal tool's sign-in needs.
 */

const UriList = t.Array(t.String({ maxLength: 2000 }), { maxItems: 50 });

// `none` is absent: an application here always authenticates.
const AuthMethod = t.Union([
	t.Literal('client_secret_basic'),
	t.Literal('client_secret_post'),
	t.Literal('private_key_jwt')
]);

const JwkSet = t.Object({ keys: t.Array(t.Record(t.String(), t.Unknown())) });

export const CreateAdministratorApplicationBody = t.Object(
	{
		clientName: t.String({ minLength: 1, maxLength: 100 }),
		redirectUris: t.Array(t.String({ maxLength: 2000 }), {
			minItems: 1,
			maxItems: 50
		}),
		postLogoutRedirectUris: t.Optional(UriList),
		tokenEndpointAuthMethod: t.Optional(AuthMethod),
		/* Whether the tool also gets a refresh token (`offline_access`); on unless it says otherwise. */
		refreshTokens: t.Optional(t.Boolean()),
		requireConsent: t.Optional(t.Boolean()),
		/* The key set a `private_key_jwt` application signs with, inline or by address. */
		jwks: t.Optional(JwkSet),
		jwksUri: t.Optional(t.String())
	},
	{ additionalProperties: false }
);

export const UpdateAdministratorApplicationBody = t.Object(
	{
		clientName: t.Optional(t.String({ minLength: 1, maxLength: 100 })),
		redirectUris: t.Optional(
			t.Array(t.String({ maxLength: 2000 }), { minItems: 1, maxItems: 50 })
		),
		postLogoutRedirectUris: t.Optional(UriList),
		tokenEndpointAuthMethod: t.Optional(AuthMethod),
		refreshTokens: t.Optional(t.Boolean()),
		requireConsent: t.Optional(t.Boolean()),
		// null removes it, as on a project application.
		jwks: t.Optional(t.Union([JwkSet, t.Null()])),
		jwksUri: t.Optional(t.Union([t.String(), t.Null()]))
	},
	{ additionalProperties: false }
);
