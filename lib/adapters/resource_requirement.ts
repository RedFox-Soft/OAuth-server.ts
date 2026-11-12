import type { ProtectedResource } from './types.js';

/*
 * An API's sign-in requirement as each store writes it (specs/130 research R1). Stored only as `requireCode: true` and
 * a number of minutes; a patch's `false` or `null` removes the key, so no backend ever holds a "no" that an older
 * reader could take for something else.
 */

export interface RequirementInput {
	requireCode?: boolean;
	signInEveryMinutes?: number | null;
}

/* The fields a new record carries. */
export function requirementFields(
	data: RequirementInput
): Pick<ProtectedResource, 'requireCode' | 'signInEveryMinutes'> {
	return {
		...(data.requireCode === true ? { requireCode: true as const } : {}),
		...(typeof data.signInEveryMinutes === 'number'
			? { signInEveryMinutes: data.signInEveryMinutes }
			: {})
	};
}

/* What a patch sets and what it removes. Keys the patch does not name are left as they are. */
export function requirementPatch(data: RequirementInput): {
	set: Pick<ProtectedResource, 'requireCode' | 'signInEveryMinutes'>;
	unset: ('requireCode' | 'signInEveryMinutes')[];
} {
	const unset: ('requireCode' | 'signInEveryMinutes')[] = [];
	if (data.requireCode === false) unset.push('requireCode');
	if (data.signInEveryMinutes === null) unset.push('signInEveryMinutes');
	return { set: requirementFields(data), unset };
}
