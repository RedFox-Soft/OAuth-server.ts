import { useCallback, useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	Select,
	Space,
	Tag,
	Typography
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { ConnectionView } from './ProvisioningPanel.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import type { BucketCan } from '../frame/can.js';
import { Link, useNavigate, useRoute } from '../frame/router.js';
import { bucketHref, userGroupHref } from '../frame/routes.js';
import {
	RenameGroupModal,
	groupsApi,
	useDeleteGroup,
	type GroupView
} from './groups/groupShared.js';

export type { GroupView };

/*
 * A bucket's groups of end users (specs/084): the list, and creating one. Each group has a page of its own
 * for its members and the acts that change who it grants; this tab lists, opens, renames and deletes.
 *
 * Creating, renaming and deleting are the bucket's owners' (`can.edit`); changing who is in a group is user
 * management and happens on the group's page.
 */
export function BucketGroupsPanel({
	bucketId,
	can,
	connections,
	onChanged
}: {
	bucketId: string;
	can: Pick<BucketCan, 'edit' | 'manageUsers'>;
	connections: ConnectionView[];
	onChanged: () => void;
}) {
	const feedback = useFeedback();
	const navigate = useNavigate();
	const deleteGroup = useDeleteGroup(bucketId);
	const { query } = useRoute();
	// Who keeps a group, from the address so a connection's page can link to the groups it keeps.
	const keptBy = query.get('keptBy') ?? undefined;
	const [groups, setGroups] = useState<GroupView[]>([]);
	const [loading, setLoading] = useState(true);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [createOpen, setCreateOpen] = useState(false);
	const [renaming, setRenaming] = useState<GroupView | null>(null);
	const [nameForm] = Form.useForm<{ displayName: string }>();

	const connectionName = (id: string) =>
		connections.find((c) => c.id === id)?.displayName ?? id;

	const fetchGroups = useCallback(async () => {
		try {
			const result = await request<{ groups: GroupView[] }>(
				'GET',
				groupsApi(bucketId)
			);
			if (result.ok) {
				setGroups(result.data.groups);
				setLoadError(null);
			} else {
				setLoadError(result.error.message);
			}
		} finally {
			setLoading(false);
		}
	}, [bucketId]);
	useEffect(() => {
		void fetchGroups();
	}, [fetchGroups]);

	async function changed() {
		await fetchGroups();
		onChanged();
	}

	async function onCreate({ displayName }: { displayName: string }) {
		const result = await request<GroupView>('POST', groupsApi(bucketId), {
			displayName
		});
		if (!result.ok) {
			feedback.failed(result, nameForm);
			return;
		}
		feedback.done(`User group ${displayName} created.`);
		setCreateOpen(false);
		nameForm.resetFields();
		void navigate(userGroupHref(bucketId, result.data.id));
	}

	function setKeptBy(value: string | undefined) {
		const params = new URLSearchParams(query);
		if (value) params.set('keptBy', value);
		else params.delete('keptBy');
		const qs = params.toString();
		void navigate(
			`${bucketHref(bucketId, 'user-groups')}${qs ? `?${qs}` : ''}`,
			{
				replace: true
			}
		);
	}

	function rowActions(group: GroupView): RowAction[] {
		const notice = group.provisionedBy
			? `Kept by ${connectionName(group.provisionedBy)} — change this group in the directory`
			: null;
		return [
			{
				key: 'open',
				label: 'Open',
				group: 'edit',
				onClick: () => void navigate(userGroupHref(bucketId, group.id))
			},
			...(can.edit
				? [
						{
							key: 'rename',
							label: 'Rename…',
							group: 'edit' as const,
							blocked: notice,
							onClick: () => setRenaming(group)
						},
						{
							key: 'delete',
							label: 'Delete…',
							group: 'danger' as const,
							blocked: notice,
							onClick: () =>
								void deleteGroup(group).then((done) => {
									if (done) void changed();
								})
						}
					]
				: [])
		];
	}

	const createButton = can.edit ? (
		<Button
			icon={<PlusOutlined />}
			onClick={() => {
				nameForm.resetFields();
				setCreateOpen(true);
			}}
		>
			New user group
		</Button>
	) : null;

	const shown = groups.filter((g) =>
		keptBy === undefined
			? true
			: keptBy === 'console'
				? !g.provisionedBy
				: g.provisionedBy === keptBy
	);

	return (
		<>
			<Space
				style={{
					marginTop: 8,
					marginBottom: 12,
					justifyContent: 'space-between',
					width: '100%'
				}}
			>
				<Typography.Title
					level={5}
					style={{ margin: 0 }}
				>
					User groups
				</Typography.Title>
				<Space>
					{connections.length > 0 && (
						<Select
							aria-label="Kept by"
							allowClear
							placeholder="Kept by"
							style={{ width: 220 }}
							value={keptBy}
							onChange={(v: string | undefined) => setKeptBy(v)}
							options={[
								{ label: 'Administrators', value: 'console' },
								...connections.map((c) => ({
									label: c.displayName,
									value: c.id
								}))
							]}
						/>
					)}
					{createButton}
				</Space>
			</Space>
			{loadError !== null ? (
				<LoadFailed
					reason={loadError}
					onRetry={() => {
						setLoading(true);
						void fetchGroups();
					}}
				/>
			) : (
				<Table<GroupView>
					rowKey="id"
					loading={loading}
					dataSource={shown}
					pagination={false}
					locale={{
						emptyText: loading ? (
							' '
						) : (
							<EmptyState
								purpose={
									keptBy
										? 'No group is kept by this.'
										: "No user groups in this bucket yet. A group's name reaches applications in the groups claim of each member's tokens."
								}
								create={keptBy ? undefined : createButton}
							/>
						)
					}}
					columns={[
						{
							title: 'Name',
							dataIndex: 'displayName',
							render: (displayName: string, group: GroupView) => (
								<Link href={userGroupHref(bucketId, group.id)}>
									{displayName}
								</Link>
							)
						},
						{ title: 'Members', dataIndex: 'memberCount' },
						{
							title: 'Kept by',
							dataIndex: 'provisionedBy',
							render: (provisionedBy: string | undefined) =>
								provisionedBy ? (
									<Tag color="purple">{connectionName(provisionedBy)}</Tag>
								) : (
									<Typography.Text type="secondary">
										administrators
									</Typography.Text>
								)
						},
						{
							title: '',
							render: (_: unknown, group: GroupView) => (
								<RowActions
									name={group.displayName}
									items={rowActions(group)}
								/>
							)
						}
					]}
				/>
			)}

			<Modal
				title="New user group"
				open={createOpen}
				onCancel={() => setCreateOpen(false)}
				onOk={() => nameForm.submit()}
				okText="Create user group"
				destroyOnHidden
			>
				<Form<{ displayName: string }>
					form={nameForm}
					layout="vertical"
					onFinish={(v) => void onCreate(v)}
				>
					<Form.Item
						name="displayName"
						label="Name"
						extra="Applications receive this name in the groups claim of each member's tokens."
						rules={[{ required: true, whitespace: true }]}
					>
						<Input autoComplete="off" />
					</Form.Item>
				</Form>
			</Modal>
			<RenameGroupModal
				bucketId={bucketId}
				group={renaming}
				onClose={() => setRenaming(null)}
				onRenamed={() => void changed()}
			/>
		</>
	);
}
