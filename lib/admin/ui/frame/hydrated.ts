import { useSyncExternalStore } from 'react';

const never = () => () => undefined;

/*
 * False on the server and for the hydrating render, true from then on. For a value only the browser
 * has — a choice kept in localStorage — so the first client frame matches the HTML it hydrates, and the
 * stored value arrives on the very next render without an effect writing state.
 */
export function useHydrated(): boolean {
	return useSyncExternalStore(
		never,
		() => true,
		() => false
	);
}
