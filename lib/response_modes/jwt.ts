import query from './query.ts';
import form_post from './form_post.ts';
import web_message from './web_message.ts';

const modes = {
	query,
	form_post,
	web_message
};

const RENDER_MODES = new Set(['form_post', 'web_message']);

export default async function jwtResponseModes(ctx, redirectUri, payload) {
	const { params } = ctx.oidc;

	let mode = 'query';
	if (params.response_mode !== 'jwt') {
		[mode] = params.response_mode.split('.');
	}

	const { IdToken } = this;
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
