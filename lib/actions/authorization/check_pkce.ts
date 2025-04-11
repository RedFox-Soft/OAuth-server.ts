import { InvalidRequest } from '../../helpers/errors.ts';
import checkFormat from '../../helpers/pkce_format.ts';

/*
 * - check presence of code code_challenge if code_challenge_method is provided
 * - enforce PKCE use for native clients using hybrid or code flow
 */
export default function checkPKCE(ctx, next) {
	const { params } = ctx.oidc;

	if (!params.response_type.includes('code')) {
		return next();
	}

	if (!params.code_challenge) {
		throw new InvalidRequest(
			'Authorization Server policy requires PKCE to be used for this request'
		);
	}
	if (!params.code_challenge_method) {
		throw new InvalidRequest('code_challenge_method must be provided');
	}
	if (params.code_challenge_method !== 'S256') {
		throw new InvalidRequest('not supported value of code_challenge_method');
	}
	checkFormat(params.code_challenge, 'code_challenge');

	return next();
}
