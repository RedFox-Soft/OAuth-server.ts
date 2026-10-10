import { useEffect, useState } from 'react';
import { Select, Typography } from 'antd';
import { groupLabel } from '../../groups/label.js';
import { useFeedback } from '../frame/feedback.js';
import { useMe } from '../frame/me.js';
import { request } from '../frame/request.js';
import { useNavigate, useRoute } from '../frame/router.js';
import { sectionHref } from '../frame/routes.js';

export interface ScopeOption {
	id: string;
	name: string;
	kind: 'personal' | 'regular' | 'system';
	role: 'owner' | 'member' | null;
	// Whether a personal group is the caller's own. Answered by the server, which is the only side that
	// sees a group's members.
	own: boolean;
}

interface ScopeView {
	activeGroupId: string;
	available: ScopeOption[];
}

/*
 * Which group the console is pointed at.
 *
 * The active scope is held on the session, so every list is scoped by the server on its next request.
 * After a switch the operator's identity is re-read and the page subtree remounts (Layout keys it by the
 * active group), so every list re-fetches at once — the consistency the old full reload bought, without
 * losing the address. The operator stays in the same section; an entity page (one bucket, one project)
 * gives way to its list, because the entity may belong to the group just left.
 */
export function ScopeSwitcher() {
	const [scope, setScope] = useState<ScopeView | null>(null);
	const [switching, setSwitching] = useState(false);
	const { reload } = useMe();
	const navigate = useNavigate();
	const { resolved } = useRoute();
	const feedback = useFeedback();

	useEffect(() => {
		void (async () => {
			const res = await fetch('/admin/api/scope');
			if (res.ok) setScope((await res.json()) as ScopeView);
		})();
	}, []);

	async function onChange(groupId: string) {
		const section =
			resolved.kind === 'page' ? resolved.route.section : undefined;
		// Through the leave guard first: unsaved edits are asked about before anything changes.
		if (section && !(await navigate(sectionHref(section), { replace: true }))) {
			return;
		}
		setSwitching(true);
		const result = await request('PUT', '/admin/api/scope', { groupId });
		setSwitching(false);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		setScope((prev) => (prev ? { ...prev, activeGroupId: groupId } : prev));
		await reload();
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
