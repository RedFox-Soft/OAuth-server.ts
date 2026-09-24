import * as formatters from './formatters.ts';
import { InvalidRequest } from './errors.ts';
import type { OIDCContext } from './oidc_context.ts';

/*
 * An assertion as well as a check: once it returns, the named parameters are known to be present, so
 * the reads that follow need no second test the type checker cannot see.
 */
export default function validatePresence<
	T extends Record<string, unknown>,
	K extends keyof T & string
>(
	oidc: OIDCContext<T>,
	...required: K[]
): asserts oidc is OIDCContext<T & { [P in K]-?: Exclude<T[P], undefined> }> {
	const missing = required.filter(
		(param) => typeof oidc.params[param] === 'undefined'
	);

	if (missing.length) {
		throw new InvalidRequest(
			`missing required ${formatters.pluralize('parameter', missing.length)} ${formatters.formatList(missing)}`
		);
	}
}
