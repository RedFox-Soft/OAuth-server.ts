import query from './query.ts';
import { formPost } from '../html/formPost.js';
import { IdToken } from 'lib/models/id_token.js';
import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';

const modes = {
	query,
	form_post: formPost
};

export default async function jwtResponseModes(
	oidc: OIDCContext<PipelineParams>,
	redirectUri: string,
	payload: Record<string, string>
): Promise<Response> {
	const { params } = oidc;

	// `jwt` alone is delivered by query; `query.jwt` and `form_post.jwt` name their carrier.
	const carrier = (params.response_mode ?? 'jwt').split('.')[0];
	const deliver = carrier === 'form_post' ? modes.form_post : modes.query;

	const token = new IdToken(oidc.client);
	token.extra = payload;

	const response = await token.issue('authorization');

	return deliver(oidc, redirectUri, { response });
}
