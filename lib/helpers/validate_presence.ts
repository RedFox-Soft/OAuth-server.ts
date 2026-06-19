import * as formatters from './formatters.ts';
import { InvalidRequest } from './errors.ts';
import type { OIDCContext } from './oidc_context.ts';

export default function validatePresence(
	oidc: OIDCContext<Record<string, unknown>>,
	...required: string[]
) {
	const missing = required.filter(
		(param) => typeof oidc.params[param] === 'undefined'
	);

	if (missing.length) {
		throw new InvalidRequest(
			`missing required ${formatters.pluralize('parameter', missing.length)} ${formatters.formatList(missing)}`
		);
	}
}
