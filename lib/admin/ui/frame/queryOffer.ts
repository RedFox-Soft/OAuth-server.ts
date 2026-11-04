import { useCallback, useRef } from 'react';
import { useNavigate, useRoute } from './router.js';

/*
 * A page that opens its create form from the address (`?add=google`, `?new=1`), for the guide's "Set this up".
 * The value is read once, when the page mounts. `offer(allowed)` hands it over a single time, and only when the
 * page's own create button would be offered: the viewer has its right and, where a plan counts what it creates,
 * the plan has room. Otherwise nothing is consumed and nothing opens. On
 * the way out the query leaves the address (replacing the entry), so a reload does not open the form again.
 */
export function useQueryOffer(name: string) {
	const { query } = useRoute();
	const navigate = useNavigate();
	const requested = useRef(query.get(name));
	const taken = useRef(false);
	return useCallback(
		(allowed: boolean): string | null => {
			if (taken.current || requested.current === null || !allowed) return null;
			taken.current = true;
			const rest = new URLSearchParams(window.location.search);
			rest.delete(name);
			const left = rest.toString();
			const search = left !== '' ? `?${left}` : '';
			void navigate(`${window.location.pathname}${search}`, {
				replace: true,
				scroll: false
			});
			return requested.current;
		},
		[name, navigate]
	);
}
