import query from './query.ts';
import { formPost } from '../html/formPost.js';
import { IdToken } from 'lib/models/id_token.js';

const modes = {
	query,
	form_post: formPost
};

export default async function jwtResponseModes(ctx, redirectUri, payload) {
	const { params } = ctx.oidc;

	let mode = 'query';
	if (params.response_mode !== 'jwt') {
		[mode] = params.response_mode.split('.');
	}

	const token = new IdToken({}, { ctx });
	token.extra = payload;

	const response = await token.issue({ use: 'authorization' });

	return modes[mode](ctx, redirectUri, { response });
}
