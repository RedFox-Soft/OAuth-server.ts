import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import { InvalidRequest } from '../../helpers/errors.ts';

export default function unsupportedRar(oidc: OIDCContext<PipelineParams>) {
	if (oidc.params.authorization_details !== undefined) {
		throw new InvalidRequest(
			`authorization_details is unsupported at the ${oidc.route}_endpoint`
		);
	}
}
