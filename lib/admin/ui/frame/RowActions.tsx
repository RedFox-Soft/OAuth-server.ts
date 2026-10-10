import type { ReactNode } from 'react';
import { Button, Dropdown, Space } from 'antd';
import type { MenuProps } from 'antd';
import { MoreOutlined } from '@ant-design/icons';

/*
 * What can be done to one row, laid out the same way in every table (specs/079 US7).
 *
 * The row's name is the link that opens it; beside it, at most one action worth a click of its own, and
 * everything else in "More". Seven buttons on a row made every row a different shape and put Delete a
 * centimetre from Edit.
 *
 * The menu is ordered by what an item does — edit, then state changes, then handing something over,
 * then, after a divider, anything that destroys or revokes — so Delete is always last and always red.
 * Items refused for the same reason fold into one disabled line that says the reason once, rather than
 * a column of greyed items the operator has to hover one by one.
 */

export type RowActionGroup = 'edit' | 'state' | 'handover' | 'danger';

export interface RowAction {
	key: string;
	/* Ends with "…" when it opens a dialog. */
	label: string;
	group: RowActionGroup;
	onClick: () => void;
	/* Why it cannot be done now; the item shows, disabled, folded with others refused for the same reason. */
	blocked?: string | null;
	icon?: ReactNode;
}

const ORDER: readonly RowActionGroup[] = [
	'edit',
	'state',
	'handover',
	'danger'
];

export function RowActions({
	name,
	inline,
	items
}: {
	/* The row's name, for the menu's accessible label. */
	name: string;
	inline?: ReactNode;
	items: readonly RowAction[];
}) {
	const open = items.filter((item) => !item.blocked);
	const blockedReasons = [
		...new Set(items.filter((item) => item.blocked).map((item) => item.blocked))
	];

	const menu: NonNullable<MenuProps['items']> = [];
	for (const group of ORDER) {
		const inGroup = open.filter((item) => item.group === group);
		if (inGroup.length === 0) continue;
		if (group === 'danger' && menu.length > 0) menu.push({ type: 'divider' });
		for (const item of inGroup) {
			menu.push({
				key: item.key,
				label: item.label,
				icon: item.icon,
				danger: group === 'danger',
				onClick: item.onClick
			});
		}
	}
	for (const reason of blockedReasons) {
		if (menu.length > 0) menu.push({ type: 'divider' });
		menu.push({
			key: `blocked:${reason ?? ''}`,
			label: reason,
			disabled: true
		});
	}

	return (
		<Space size={4}>
			{inline}
			{menu.length > 0 && (
				<Dropdown
					menu={{ items: menu }}
					trigger={['click']}
				>
					<Button
						size="small"
						type="text"
						icon={<MoreOutlined />}
						aria-label={`More actions for ${name}`}
					/>
				</Dropdown>
			)}
		</Space>
	);
}
