/*
 * The arithmetic of an API's sign-in requirement (specs/130 research R3), with nothing to import: the console's "Check
 * access" bundles it (specs/131 research R5), and it cannot take the server's configuration. Whether the sign-in had a
 * code is worked out by the caller (the server from the token's `acr`, the console from what the administrator says).
 *
 * A missing or unreadable sign-in time is never recent: `undefined` in the arithmetic would be `NaN`, and every
 * comparison with `NaN` is false, which would read as a pass.
 */

export interface SignInRule {
	readonly code: boolean;
	readonly maxAgeSeconds?: number;
}

export interface UnmetRequirement {
	/* A code from an authenticator app is required and the sign-in had none. */
	readonly code: boolean;
	/* A sign-in no older than the requirement is needed and this one is older, or its time is unknown. */
	readonly recent: boolean;
}

export function requirementUnmet(
	signIn: SignInRule | undefined,
	facts: {
		readonly withCode: boolean;
		/* Seconds since the epoch. */
		readonly authTime: number | null | undefined;
	},
	nowSeconds: number
): UnmetRequirement | null {
	if (!signIn) return null;
	const code = signIn.code && !facts.withCode;
	const maxAge = signIn.maxAgeSeconds;
	const authTime = facts.authTime;
	const recent =
		maxAge !== undefined &&
		!(
			typeof authTime === 'number' &&
			Number.isFinite(authTime) &&
			nowSeconds - authTime <= maxAge
		);
	return code || recent ? { code, recent } : null;
}
