import query from './query.ts';
import { formPost } from '../html/formPost.js';
import { provider } from 'lib/provider.js';

const modes = {
	query,
	form_post: formPost
};

const RENDER_MODES = new Set(['form_post']);

export default async function jwtResponseModes(ctx, redirectUri, payload) {
	const { params } = ctx.oidc;

	let mode = 'query';
	if (params.response_mode !== 'jwt') {
		[mode] = params.response_mode.split('.');
	}

	const { IdToken } = provider;
	const token = new IdToken({}, { ctx });
	token.extra = payload;

	const response = await token.issue({ use: 'authorization' });

	if (RENDER_MODES.has(mode)) {
		if ('error' in payload && payload.error !== 'server_error') {
			ctx.status = 400;
		}
	}

	return modes[mode](ctx, redirectUri, { response });
}
