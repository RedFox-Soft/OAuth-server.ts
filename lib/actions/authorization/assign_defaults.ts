import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
/*
 * assign max_age and acr_values if it is not provided explictly but is configured with default
 * values on the client
 */
export default function assignDefaults(oidc: OIDCContext<PipelineParams>) {
	const { params, client } = oidc;

	if (!params.acr_values && client.defaultAcrValues) {
		params.acr_values = client.defaultAcrValues.join(' ');
	}

	if (params.max_age === undefined && client.defaultMaxAge !== undefined) {
		// A number, as a requested max_age is once validated: checkMaxAge turns only a numeric 0 into
		// prompt=login, so a string "0" left a client's default_max_age of 0 to a clock-second race.
		params.max_age = client.defaultMaxAge;
	}
}
