import type { ProtectedResource } from './types.js';

/*
 * An API's sign-in requirement as each store writes it (specs/130 research R1, specs/143 R1). Stored only as
 * `requirePasskey: true`, `requireCode: true` and a number of minutes; `requirePasskey: true` includes two-step
 * sign-in and removes `requireCode` so no record ever stores a contradiction. A patch's `false` or `null` removes
 * the key, so no backend ever holds a "no" that an older reader could take for something else.
 */

export interface RequirementInput {
	requireCode?: boolean;
	requirePasskey?: boolean;
	signInEveryMinutes?: number | null;
}

type RequirementKey = 'requireCode' | 'requirePasskey' | 'signInEveryMinutes';

/* The fields a new record carries. */
export function requirementFields(
	data: RequirementInput
): Pick<ProtectedResource, RequirementKey> {
	const passkey = data.requirePasskey === true;
	return {
		...(passkey ? { requirePasskey: true as const } : {}),
		...(!passkey && data.requireCode === true
			? { requireCode: true as const }
			: {}),
		...(typeof data.signInEveryMinutes === 'number'
			? { signInEveryMinutes: data.signInEveryMinutes }
			: {})
	};
}

/* What a patch sets and what it removes. Keys the patch does not name are left as they are. */
export function requirementPatch(data: RequirementInput): {
	set: Pick<ProtectedResource, RequirementKey>;
	unset: RequirementKey[];
} {
	const unset: RequirementKey[] = [];
	if (data.requirePasskey === true || data.requireCode === false) {
		unset.push('requireCode');
	}
	if (data.requirePasskey === false) unset.push('requirePasskey');
	if (data.signInEveryMinutes === null) unset.push('signInEveryMinutes');
	return { set: requirementFields(data), unset };
}
