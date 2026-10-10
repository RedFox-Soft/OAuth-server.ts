import type { ScopeOption } from '../pages/ScopeSwitcher.js';

/*
 * The groups the console offers as a move's destination (specs/075): the caller's scopes, less the group
 * the container is in and less any personal group that is not the caller's own.
 *
 * Built from the scope list because that list is already exactly the groups the caller may work in — a
 * super administrator's omits other administrators' personal groups for the same reason the move refuses
 * them. The second filter restates that refusal here so the control never offers a destination the server
 * would turn down, whichever caller the list was built for.
 */
export function moveDestinations(
	options: readonly ScopeOption[],
	sourceGroupId: string
): ScopeOption[] {
	return options.filter(
		(option) =>
			option.id !== sourceGroupId && (option.kind !== 'personal' || option.own)
	);
}
