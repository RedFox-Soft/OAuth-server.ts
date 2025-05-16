/*
 * Validates the max_age parameter and handles max_age=0 to prompt=login translation
 */
export default function checkMaxAge(ctx) {
	const maxAge = ctx.oidc.params.max_age;
	if (maxAge === 0) {
		const { prompts } = ctx.oidc;
		ctx.oidc.params.max_age = undefined;
		if (!prompts.has('login')) {
			prompts.add('login');
			ctx.oidc.params.prompt = [...prompts].join(' ');
		}
	}
}
