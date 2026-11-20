/*
 * The login-prompt reasons that stop a sign-in for want of a code from an authenticator app: an application's own
 * requirement (specs/127) and a requested API's (specs/130); and for want of a passkey, an application's requirement of
 * one (specs/142). Read wherever the refusal page, the loop guard and the code notice decide, so each is treated alike
 * while keeping its own words. The strings are the prompt's `reason` values, already public in the interaction details.
 */
export const CODE_REASONS: ReadonlySet<string> = new Set([
	'app_passkey',
	'second_factor',
	'resource_code'
]);

export function asksForCode(reasons: readonly string[]): boolean {
	return reasons.some((reason) => CODE_REASONS.has(reason));
}
