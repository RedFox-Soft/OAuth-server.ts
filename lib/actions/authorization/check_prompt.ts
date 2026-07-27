import { InvalidRequest } from '../../helpers/errors.ts';
import { supportedPrompts } from '../../addon/index.js';

/*
 * Checks that all requested prompts are supported and validates prompt none is not combined with
 * other prompts
 */
export default function checkPrompt(oidc) {
	if (oidc.params.prompt !== undefined) {
		const { prompts } = oidc;
		// Derived from the resolved policy per request, so a prompt registered after provider
		// initialisation is accepted rather than rejected as unsupported.
		const supported = supportedPrompts();

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
