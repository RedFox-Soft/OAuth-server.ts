import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import {
	validateRequestContext,
	validateBindingMessage
} from '../../addon/index.js';

export default async function checkCibaContext(
	oidc: OIDCContext<PipelineParams>
) {
	await Promise.all([
		validateRequestContext(oidc, oidc.params.request_context),
		validateBindingMessage(oidc, oidc.params.binding_message)
	]);
}
