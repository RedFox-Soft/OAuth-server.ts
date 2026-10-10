import { describe, it, expect } from 'bun:test';

import { moveDestinations } from 'lib/admin/ui/ownership/model.ts';
import type { ScopeOption } from 'lib/admin/ui/pages/ScopeSwitcher.tsx';

const KINDS: ScopeOption['kind'][] = ['personal', 'regular', 'system'];

/*
 * What the server accepts as a destination, declared rather than derived: not the group the container is
 * already in, and not a personal group unless it is the caller's own. Every other refusal (a group the
 * caller does not belong to, Super administrators) never reaches the console, because the scope list the
 * options come from does not contain it.
 */
function accepted(option: ScopeOption, sourceGroupId: string): boolean {
	if (option.id === sourceGroupId) return false;
	return option.kind !== 'personal' || option.own;
}

/**
 * @proves The console offers as a move's destination exactly the groups the server accepts, for every
 * kind of group a caller's scope list can hold.
 */
describe('the destinations offered for a move', () => {
	const options: ScopeOption[] = KINDS.flatMap((kind) =>
		[true, false].flatMap((own) =>
			(['owner', 'member', null] as const).map((role) => ({
				id: `${kind}-${String(own)}-${String(role)}`,
				name: kind,
				kind,
				role,
				own
			}))
		)
	);

	it.each(options.map((o) => [o.id] as const))(
		'offers %s exactly when the server accepts it, as the source and as any other group',
		(id) => {
			const option = options.find((o) => o.id === id);
			if (!option) throw new Error(`no option ${id}`);
			for (const source of [option.id, 'some-other-group']) {
				expect(moveDestinations([option], source).includes(option)).toBe(
					accepted(option, source)
				);
			}
		}
	);
});
