import { InvalidRequest } from '../../helpers/errors.ts';
import instance from '../../helpers/weak_cache.ts';

/*
 * Checks that all requested prompts are supported and validates prompt none is not combined with
 * other prompts
 */
export default function checkPrompt(oidc) {
	if (oidc.params.prompt !== undefined) {
		const { prompts } = oidc;
		const supported = instance(oidc.provider).configuration.prompts;

		for (const prompt of prompts) {
			if (!supported.has(prompt)) {
				throw new InvalidRequest('unsupported prompt value requested');
			}
		}

		if (prompts.has('none') && prompts.size !== 1) {
			throw new InvalidRequest('prompt none must only be used alone');
		}
	}
}
