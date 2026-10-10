import {
	createContext,
	useCallback,
	useContext,
	useMemo,
	useState,
	type ReactNode
} from 'react';
import type { AdminContext } from '../../auth/rbac.js';
import { request } from './request.js';

/*
 * Who the operator is, for the whole console. Seeded from the server render and re-read after anything
 * that changes it — switching group above all, which used to reload the page for exactly this reason:
 * a console where half the screens knew the new group and half the old one.
 */

export interface MeCan {
	createBucket: boolean;
	createHost: boolean;
	createProject: boolean;
	createGroup: boolean;
	instance: boolean;
}

export type Me = AdminContext & { verified?: boolean; can?: MeCan };

interface MeValue {
	me: Me | null;
	reload: () => Promise<void>;
}

const MeContext = createContext<MeValue | null>(null);

export function MeProvider({
	initial,
	children
}: {
	initial: Me | null;
	children: ReactNode;
}) {
	const [me, setMe] = useState<Me | null>(initial);
	const reload = useCallback(async () => {
		const result = await request<Me>('GET', '/admin/api/me');
		if (result.ok) setMe(result.data);
	}, []);
	const value = useMemo(() => ({ me, reload }), [me, reload]);
	return <MeContext.Provider value={value}>{children}</MeContext.Provider>;
}

export function useMe(): MeValue {
	const value = useContext(MeContext);
	if (!value) throw new Error('the console identity is not mounted');
	return value;
}

/*
 * The operator's instance-wide rights. Until the server states them (`me.can`), they fall back to what
 * the privilege alone implies, so the console never offers less than it did.
 */
export function meCan(me: Me | null): MeCan {
	if (me?.can) return me.can;
	const instance = me?.superAdmin === true;
	return {
		createBucket: me !== null,
		createHost: instance,
		createProject: me !== null,
		createGroup: me !== null,
		instance
	};
}
