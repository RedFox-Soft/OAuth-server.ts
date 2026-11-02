import { t } from 'elysia';

/*
 * Bodies of the connected-service routes (specs/117 contracts/admin-surface.md). In a schema module, never inline,
 * because lib/mcp/catalogue.ts imports these and must never import a route module. Restated with Elysia's `t` for
 * the reason lib/admin/plans/schema.ts gives (wiki/concepts/typebox-dual-type-resolution.md).
 */

const Url = t.String({ minLength: 1, maxLength: 2048 });
const ClientId = t.String({ minLength: 1, maxLength: 512 });
const ClientSecret = t.String({ minLength: 1, maxLength: 4096 });
const DisplayName = t.String({ minLength: 1, maxLength: 80 });
const ScopeList = t.Array(t.String({ minLength: 1, maxLength: 200 }), {
	maxItems: 50
});
const Path = t.String({ minLength: 1, maxLength: 200 });
/* The applications allowed to obtain this service's tokens (specs/118 R4); the whole list, replaced. */
const Applications = t.Array(t.String({ minLength: 1, maxLength: 512 }), {
	maxItems: 100,
	uniqueItems: true
});

const IdentitySourceBody = t.Union([
	t.Object(
		{
			source: t.Literal('endpoint'),
			url: Url,
			idPath: Path,
			labelPath: t.Optional(Path)
		},
		{ additionalProperties: false }
	),
	t.Object(
		{ source: t.Literal('token'), idPath: Path, labelPath: t.Optional(Path) },
		{ additionalProperties: false }
	)
]);

/*
 * One object rather than a union per kind: an MCP tool's input schema must be an object, and the console form is one.
 * Which fields each kind needs is the service's to check (lib/admin/connected-services/service.ts), with an answer
 * that names the field.
 */
export const CreateServiceBody = t.Object(
	{
		kind: t.Union([
			t.Literal('catalogue'),
			t.Literal('oidc'),
			t.Literal('oauth2')
		]),
		/* `kind: "catalogue"`: which service. */
		catalogueId: t.Optional(
			t.Union([
				t.Literal('google'),
				t.Literal('github'),
				t.Literal('slack'),
				t.Literal('microsoft')
			])
		),
		/* Microsoft only: "common", "organizations", "consumers" or a directory id. */
		tenant: t.Optional(t.String({ minLength: 1, maxLength: 100 })),
		/* `kind: "oidc"`: the issuer, whose discovery document gives the endpoints. */
		issuer: t.Optional(Url),
		/* `kind: "oauth2"`: the endpoints, and where the provider says who the account is (required). */
		authorizationEndpoint: t.Optional(Url),
		tokenEndpoint: t.Optional(Url),
		identity: t.Optional(IdentitySourceBody),
		revocationEndpoint: t.Optional(Url),
		clientId: ClientId,
		clientSecret: ClientSecret,
		scopes: t.Optional(ScopeList),
		/* Required except for a catalogue service, which is named after its provider unless given one. */
		displayName: t.Optional(DisplayName),
		applications: t.Optional(Applications)
	},
	{ additionalProperties: false }
);

/*
 * What may change. The provider and the client id are absent on purpose: the tokens of every connected account
 * belong to that registration (FR-006). They are listed as refusable so a request naming them is answered with
 * why, rather than with an unknown-field error that hides the reason.
 */
export const UpdateServiceBody = t.Object(
	{
		clientSecret: t.Optional(ClientSecret),
		scopes: t.Optional(ScopeList),
		displayName: t.Optional(DisplayName),
		authorizationEndpoint: t.Optional(Url),
		tokenEndpoint: t.Optional(Url),
		identity: t.Optional(IdentitySourceBody),
		revocationEndpoint: t.Optional(Url),
		applications: t.Optional(Applications),
		kind: t.Optional(t.String()),
		catalogueId: t.Optional(t.String()),
		issuer: t.Optional(t.String()),
		tenant: t.Optional(t.String()),
		clientId: t.Optional(t.String())
	},
	{ additionalProperties: false }
);
