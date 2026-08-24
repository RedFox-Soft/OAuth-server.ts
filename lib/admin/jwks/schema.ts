import { t } from 'elysia';

/*
 * RSA signing algorithms offered for generation. EC/OKP and encryption-use keys are out of scope for
 * key *generation*; such keys may still exist in the store if provisioned out of band, and are
 * displayed and removable.
 *
 * Declared here rather than in `service.ts` so the MCP tool catalogue can build an agent-facing schema
 * from the same list the service validates against — the service module reaches the adapters and from
 * there `lib/adapters/mongodb/db.ts`, which connects at import time.
 */
export const SUPPORTED_ALGS = ['RS256', 'RS384', 'RS512'] as const;
export type SupportedAlg = (typeof SUPPORTED_ALGS)[number];

/*
 * Describes the generate-key body for callers that need to be told what to send — the MCP tool
 * schema, principally. The route itself deliberately declares a loose `t.Record` and validates in the
 * service, so a bad `alg` answers in the admin_error shape rather than as a generic TypeBox error; see
 * `lib/admin/jwks/routes.ts`. This schema is therefore documentation of the same rule, not a second
 * enforcement of it, and it is built from SUPPORTED_ALGS so it cannot describe a different set.
 */
export const GenerateKeyBody = t.Object({
	alg: t.Optional(
		t.Union(
			SUPPORTED_ALGS.map((alg) => t.Literal(alg)) as unknown as [
				ReturnType<typeof t.Literal>
			]
		)
	)
});
