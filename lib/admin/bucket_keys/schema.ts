import { t } from 'elysia';
import { SUPPORTED_ALGS } from '../jwks/schema.js';

/*
 * The body of a bucket key generation. The same algorithm list the instance key set offers, for the
 * same reason — a deployment targeting a profile that requires PS256 or ES256 has to be able to make
 * one here — and declared in a schema module so the MCP catalogue can describe it without importing a
 * route module.
 *
 * Declared strictly, unlike the instance route's loose body: an unknown algorithm is the only thing
 * the service refuses, and TypeBox refusing it first answers with the same 422 an agent is told about.
 */
export const GenerateBucketKeyBody = t.Object(
	{
		alg: t.Union(
			SUPPORTED_ALGS.map((alg) => t.Literal(alg)) as unknown as [
				ReturnType<typeof t.Literal>
			]
		)
	},
	{ additionalProperties: false }
);

export const BucketKeyParams = t.Object({
	id: t.String(),
	kid: t.String()
});
