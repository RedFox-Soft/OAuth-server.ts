/*
 * Validates the max_age parameter and handles max_age=0 to prompt=login translation
 */
export default function checkMaxAge(oidc) {
	const maxAge = oidc.params.max_age;
	if (maxAge === 0) {
		const { prompts } = oidc;
		oidc.params.max_age = undefined;
		if (!prompts.has('login')) {
			prompts.add('login');
			oidc.params.prompt = [...prompts].join(' ');
		}
	}
}
