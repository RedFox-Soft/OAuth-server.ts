import { useEffect, useState } from 'react';
import { Select, Typography } from 'antd';
import { groupLabel } from '../groupLabel.js';

export interface ScopeOption {
	id: string;
	name: string;
	kind: 'personal' | 'regular' | 'system';
	role: 'owner' | 'member' | null;
	// Whether a personal group is the caller's own. Answered by the server, which is the only side that
	// can: a shared personal group may have promoted a second owner, so `role` does not settle it.
	own: boolean;
}

interface ScopeView {
	activeGroupId: string;
	available: ScopeOption[];
}

/*
 * Which group the console is pointed at.
 *
 * A full page reload on change, rather than a context that re-fetches every list. The active scope is
 * held on the session, so every list in the console is already scoped by the server on its next
 * request — reloading gets all of them consistently, and avoids a half-switched console where the
 * projects table has caught up and the buckets table has not.
 */
export function ScopeSwitcher() {
	const [scope, setScope] = useState<ScopeView | null>(null);
	const [switching, setSwitching] = useState(false);

	useEffect(() => {
		(async () => {
			const res = await fetch('/admin/api/scope');
			if (res.ok) setScope((await res.json()) as ScopeView);
		})();
	}, []);

	async function onChange(groupId: string) {
		setSwitching(true);
		try {
			const res = await fetch('/admin/api/scope', {
				method: 'PUT',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ groupId })
			});
			if (res.ok) window.location.reload();
		} finally {
			setSwitching(false);
		}
	}

	// Nothing to switch between: one scope, which the server has already picked. A super administrator
	// is never in this case — the system group is always among the choices.
	if (!scope || scope.available.length < 2) return null;

	return (
		<>
			<Typography.Text type="secondary">Scope</Typography.Text>
			<Select
				value={scope.activeGroupId}
				loading={switching}
				onChange={onChange}
				style={{ minWidth: 200 }}
				options={scope.available.map((g) => ({
					value: g.id,
					label: groupLabel(g)
				}))}
			/>
		</>
	);
}
