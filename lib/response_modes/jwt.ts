import { IdToken } from 'lib/models/id_token.js';
import type { OIDCContext } from 'lib/helpers/oidc_context.js';
import type { PipelineParams } from 'lib/consts/param_list.js';
import {
	describeFormPost,
	describeQuery,
	send,
	type AnswerDescription
} from './describe.ts';

export async function describeJwt(
	oidc: OIDCContext<PipelineParams>,
	redirectUri: string,
	payload: Record<string, string>
): Promise<AnswerDescription> {
	const { params } = oidc;

	// `jwt` alone is delivered by query; `query.jwt` and `form_post.jwt` name their carrier.
	const carrier = (params.response_mode ?? 'jwt').split('.')[0];

	const token = new IdToken(oidc.client, {}, oidc.bucket);
	token.extra = payload;

	const response = await token.issue('authorization');

	return carrier === 'form_post'
		? describeFormPost(redirectUri, { response })
		: describeQuery(redirectUri, { response });
}

export default async function jwtResponseModes(
	oidc: OIDCContext<PipelineParams>,
	redirectUri: string,
	payload: Record<string, string>
): Promise<Response> {
	return send(oidc, await describeJwt(oidc, redirectUri, payload));
}
