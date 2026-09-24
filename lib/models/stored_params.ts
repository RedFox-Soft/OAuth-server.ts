import { Type as t } from '@sinclair/typebox';
import type { PipelineParams } from '../consts/param_list.ts';

/*
 * The authorization pipeline's own parameters, stored by the artifact that continues the request later:
 * an interaction, a device code, a backchannel authentication request. Each is written from
 * `oidc.params` after the endpoint validated it, so this states that type rather than checking it —
 * only top-level keys are filtered on save (formats/opaque.ts), and re-validating what the pipeline
 * already accepted would add a refusal the server does not make.
 */
export const StoredParams = t.Unsafe<PipelineParams>(
	t.Record(t.String(), t.Unknown())
);
