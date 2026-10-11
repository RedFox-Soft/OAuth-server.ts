import { useEffect, useState } from 'react';
import { Button, Typography } from 'antd';
import {
	focusScopeSwitcher,
	scopeOptionLabel,
	type ScopeOption
} from '../pages/ScopeSwitcher.js';
import { request } from './request.js';

/*
 * The first line of a creation dialog: which group the new thing will belong to (specs/085). Created in the
 * wrong group, it has to be moved, which is a previewed act; said here, it costs a glance.
 *
 * "Change" closes the dialog rather than opening a chooser over it, and hands focus to the header's switcher,
 * which is the one place the destination is chosen.
 */
export function CreateDestination({ onChange }: { onChange: () => void }) {
	const [group, setGroup] = useState<ScopeOption | null>(null);

	useEffect(() => {
		void (async () => {
			const result = await request<{
				activeGroupId: string;
				available: ScopeOption[];
			}>('GET', '/admin/api/scope');
			if (result.ok) {
				setGroup(
					result.data.available.find(
						(g) => g.id === result.data.activeGroupId
					) ?? null
				);
			}
		})();
	}, []);

	if (!group) return null;
	return (
		<Typography.Paragraph>
			Will be created in{' '}
			<Typography.Text strong>{scopeOptionLabel(group)}</Typography.Text> ·{' '}
			<Button
				type="link"
				size="small"
				style={{ padding: 0 }}
				onClick={() => {
					onChange();
					// After the dialog's close animation, which otherwise returns focus to what opened it.
					window.setTimeout(focusScopeSwitcher, 350);
				}}
			>
				Change
			</Button>
		</Typography.Paragraph>
	);
}
