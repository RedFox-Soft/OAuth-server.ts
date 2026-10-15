import { createContext, useContext } from 'react';

/*
 * The instance's own host (ISSUER's, port included), as the server rendered it into `window.PROPS`. A
 * subdomain project's address is `<slug>.<this>`, and the record holds only the slug (specs/101).
 */
const InstanceHostContext = createContext('');

export const InstanceHostProvider = InstanceHostContext.Provider;

export function useInstanceHost(): string {
	return useContext(InstanceHostContext);
}
