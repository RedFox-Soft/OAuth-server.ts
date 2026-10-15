import { useEffect, useState } from 'react';
import { Select, Tooltip, Typography } from 'antd';
import { InfoCircleOutlined } from '@ant-design/icons';
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

const SCOPE_SWITCHER_ID = 'scope-switcher';

/*
 * A group as the switcher and the Groups list name it. An operator's own personal group says that nobody
 * else is in it, so it is not mistaken for a place to share things (specs/085).
 */
export function scopeOptionLabel(g: ScopeOption): string {
	return g.kind === 'personal' && g.own ? 'Personal · Only you' : groupLabel(g);
}

interface ScopeView {
	activeTeamId: string;
	available: ScopeOption[];
}

/*
 * Which team the console is pointed at.
 *
 * The active scope is held on the session, so every list is scoped by the server on its next request.
 * After a switch the operator's identity is re-read and the page subtree remounts (Layout keys it by the
 * active group), so every list re-fetches at once — the consistency the old full reload bought, without
 * losing the address. The operator stays in the same section; an entity page (one bucket)
 * gives way to its list, because the entity may belong to the group just left.
 */
export function ScopeSwitcher() {
	const [scope, setScope] = useState<ScopeView | null>(null);
	const [switching, setSwitching] = useState(false);
	const { me, reload } = useMe();
	const superAdmin = me?.superAdmin === true;
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
		const result = await request('PUT', '/admin/api/scope', {
			teamId: groupId
		});
		setSwitching(false);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		setScope((prev) => (prev ? { ...prev, activeTeamId: groupId } : prev));
		await reload();
	}

	if (!scope) return null;
	const active = scope.available.find((g) => g.id === scope.activeTeamId);
	/*
	 * Named by what it does (specs/085). A super administrator's lists show the whole instance whatever is
	 * chosen, so for them the control only decides where new buckets land; for everyone else it
	 * is the group they are working in.
	 */
	const label = superAdmin ? (
		<Typography.Text type="secondary">
			Create in{' '}
			<Tooltip title="Lists show the whole instance. This decides which team new projects are created in.">
				<InfoCircleOutlined aria-label="What Create in means" />
			</Tooltip>
		</Typography.Text>
	) : (
		<Typography.Text type="secondary">Team</Typography.Text>
	);

	// One group: nothing to switch between, so its name is plain text.
	if (scope.available.length < 2) {
		return active ? (
			<>
				{label}
				<Typography.Text
					id={SCOPE_SWITCHER_ID}
					tabIndex={-1}
				>
					{scopeOptionLabel(active)}
				</Typography.Text>
			</>
		) : null;
	}

	return (
		<>
			{label}
			<Select
				id={SCOPE_SWITCHER_ID}
				aria-label={superAdmin ? 'Create in' : 'Team'}
				value={scope.activeTeamId}
				loading={switching}
				onChange={onChange}
				style={{ minWidth: 200 }}
				options={scope.available.map((g) => ({
					value: g.id,
					label: scopeOptionLabel(g)
				}))}
			/>
		</>
	);
}
