import { useCallback, useEffect, useState } from 'react';
import { Button, Select, Space, Table, Tag, Typography } from 'antd';
import { bucketHref } from '../../frame/routes.js';
import { Link } from '../../frame/router.js';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import type { BucketCan } from '../../frame/can.js';
import { EmptyState } from '../../frame/states.js';
import type { GroupView } from '../BucketGroupsPanel.js';
import type { EndUser } from './endUser.js';

type Membership = NonNullable<EndUser['groups']>[number];

/*
 * The person's groups, changed one membership at a time (specs/082 FR-012): each add or remove is one
 * request through the group's own routes, so nothing is left half-saved and the audit trail reads the same
 * as a change made from the group. A directory's groups are its own and are shown without controls.
 */
export function UserGroupsTab({
	bucketId,
	user,
	can,
	connectionName,
	onChanged
}: {
	bucketId: string;
	user: EndUser;
	can: BucketCan;
	connectionName: (id: string) => string;
	onChanged: () => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [groups, setGroups] = useState<GroupView[]>([]);
	const [adding, setAdding] = useState<string | undefined>(undefined);
	const [busy, setBusy] = useState(false);
	const [loading, setLoading] = useState(true);
	const groupsApi = `/admin/api/projects/${encodeURIComponent(bucketId)}/groups`;

	const fetchGroups = useCallback(async () => {
		try {
			const result = await request<{ groups: GroupView[] }>('GET', groupsApi);
			if (result.ok) setGroups(result.data.groups);
		} finally {
			setLoading(false);
		}
	}, [groupsApi]);
	useEffect(() => {
		void fetchGroups();
	}, [fetchGroups]);

	const memberships = user.groups ?? [];
	const inGroup = new Set(memberships.map((g) => g.id));
	const addable = groups.filter((g) => !g.provisionedBy && !inGroup.has(g.id));

	async function onAdd() {
		const group = groups.find((g) => g.id === adding);
		if (!group) return;
		setBusy(true);
		try {
			const result = await request(
				'POST',
				`${groupsApi}/${encodeURIComponent(group.id)}/members`,
				{ userIds: [user._id] }
			);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			feedback.done(`${user.email} added to ${group.displayName}.`);
			setAdding(undefined);
			onChanged();
		} finally {
			setBusy(false);
		}
	}

	async function onRemove(group: Membership) {
		const agreed = await confirm('userGroup.member.remove', {
			target: user.email,
			consequences: [
				`Their next token no longer names ${group.displayName} in its groups claim.`
			]
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			`${groupsApi}/${encodeURIComponent(group.id)}/members/${encodeURIComponent(user._id)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`${user.email} removed from ${group.displayName}.`);
		onChanged();
	}

	return (
		<>
			{can.manageUsers && (
				<Space.Compact
					style={{ marginBottom: 16, maxWidth: 480, width: '100%' }}
				>
					<Select
						style={{ width: '100%' }}
						placeholder={
							addable.length > 0
								? 'Add to group'
								: 'No other group administrators keep'
						}
						loading={loading}
						disabled={addable.length === 0}
						value={adding}
						onChange={setAdding}
						showSearch={{ optionFilterProp: 'label' }}
						options={addable.map((g) => ({
							label: g.displayName,
							value: g.id
						}))}
						aria-label="Add to group"
					/>
					<Button
						type="primary"
						disabled={!adding}
						loading={busy}
						onClick={() => void onAdd()}
					>
						Add
					</Button>
				</Space.Compact>
			)}
			<Table<Membership>
				rowKey="id"
				dataSource={memberships}
				pagination={false}
				locale={{
					emptyText: (
						<EmptyState purpose="Not in any group. Groups are sent to applications in the groups claim." />
					)
				}}
				columns={[
					{
						title: 'Group',
						dataIndex: 'displayName',
						render: (name: string) => (
							<Link href={bucketHref(bucketId, 'groups')}>{name}</Link>
						)
					},
					{
						title: 'Managed by',
						key: 'managedBy',
						render: (_: unknown, group: Membership) =>
							group.provisionedBy ? (
								<Tag color="purple">{connectionName(group.provisionedBy)}</Tag>
							) : (
								<Typography.Text type="secondary">Console</Typography.Text>
							)
					},
					{
						title: '',
						key: 'remove',
						render: (_: unknown, group: Membership) =>
							can.manageUsers && !group.provisionedBy ? (
								<Button
									size="small"
									onClick={() => void onRemove(group)}
								>
									Remove
								</Button>
							) : null
					}
				]}
			/>
		</>
	);
}
