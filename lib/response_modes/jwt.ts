import query from './query.ts';
import { formPost } from '../html/formPost.js';
import { IdToken } from 'lib/models/id_token.js';

const modes = {
	query,
	form_post: formPost
};

export default async function jwtResponseModes(oidc, redirectUri, payload) {
	const { params } = oidc;

	let mode = 'query';
	if (params.response_mode !== 'jwt') {
		[mode] = params.response_mode.split('.');
	}

	const token = new IdToken(oidc.client);
	token.extra = payload;

	const response = await token.issue('authorization');

	return modes[mode](oidc, redirectUri, { response });
}
