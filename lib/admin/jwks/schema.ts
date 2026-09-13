import { t } from 'elysia';
import { ECSignAlg, OKPSignAlg, RSASignAlg } from 'lib/configs/jwaConsts.js';

/*
 * The asymmetric signing algorithms offered for generation — every one this server knows, taken
 * from the algorithm register itself rather than restated, so the two cannot disagree.
 *
 * It used to be the three RSA `RS*` algorithms, on the reasoning that EC and OKP keys could be
 * provisioned out of band. That reasoning had a cost nobody had measured: FAPI 2.0 requires PS256 or
 * ES256, so a deployment targeting that profile could not be assembled through this server's own
 * console at all — the operator had to write a key straight into the store. A management API that
 * cannot produce the keys its own profiles require is not a management API.
 *
 * `EdDSA` and `Ed25519` both appear, and produce the same kind of key. That is not a duplicate: they
 * are distinct `alg` identifiers on the wire, and key selection matches a key's declared `alg`
 * exactly — so a deployment whose clients ask for one cannot be served by a key stamped the other.
 *
 * Encryption-use keys remain out of scope for generation; such keys may still exist in the store if
 * provisioned out of band, and are displayed and removable.
 *
 * Declared here rather than in `service.ts` so the MCP tool catalogue can build an agent-facing schema
 * from the same list the service validates against — the service module reaches the adapters and from
 * there `lib/adapters/mongodb/db.ts`, which connects at import time. `jwaConsts` is import-free, so
 * reading it here adds no edge to that graph.
 */
export const SUPPORTED_ALGS = [
	...RSASignAlg,
	...ECSignAlg,
	...OKPSignAlg
] as const;
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
