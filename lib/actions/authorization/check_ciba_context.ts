import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import {
	validateRequestContext,
	validateBindingMessage
} from '../../addon/index.js';

export default async function checkCibaContext(oidc: OIDCContext) {
	await Promise.all([
		validateRequestContext(oidc, oidc.params.request_context),
		validateBindingMessage(oidc, oidc.params.binding_message)
	]);
}
