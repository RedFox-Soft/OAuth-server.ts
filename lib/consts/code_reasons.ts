/*
 * The login-prompt reasons that stop a sign-in for want of a code from an authenticator app: an application's own
 * requirement (specs/127) and a requested API's (specs/130). Read wherever the refusal page, the loop guard and the
 * code notice decide, so an API's code is treated as an application's while each keeps its own words. The strings are
 * the prompt's `reason` values, already public in the interaction details.
 */
export const CODE_REASONS: ReadonlySet<string> = new Set([
	'second_factor',
	'resource_code'
]);

export function asksForCode(reasons: readonly string[]): boolean {
	return reasons.some((reason) => CODE_REASONS.has(reason));
}
