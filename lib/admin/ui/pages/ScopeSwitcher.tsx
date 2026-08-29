import { useEffect, useState } from 'react';
import { Select, Typography } from 'antd';

export interface ScopeOption {
	id: string;
	name: string;
	kind: 'personal' | 'regular' | 'system';
	role: 'owner' | 'member' | null;
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

	// A super administrator belongs to no group, so there is nothing to switch between and the control
	// would only offer a choice that changes nothing they can see.
	if (!scope || scope.available.length === 0) return null;

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
					// A personal group is labelled for what it is rather than by its name, which is the
					// administrator's own email and reads oddly in a list of companies.
					label: g.kind === 'personal' ? 'Personal' : g.name
				}))}
			/>
		</>
	);
}
