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
	Typography,
	Popconfirm
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { ConnectionView } from './ProvisioningPanel.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { ACTIONS } from '../frame/actions.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import type { BucketCan } from '../frame/can.js';

/* What `GET …/groups` answers for each group. */
export interface GroupView {
	id: string;
	displayName: string;
	externalId?: string;
	provisionedBy?: string;
	memberCount: number;
}

interface MemberView {
	id: string;
	email: string | null;
	userName?: string;
}

/* The bucket's users the member picker offers. */
export interface PickableUser {
	_id: string;
	email: string;
}

const PAGE = 100;

const REMOVE_MEMBER = ACTIONS['userGroup.member.remove'];

/*
 * A bucket's groups of end users. Their names are what relying parties receive in the `groups` claim, so a
 * rename is stated as such. A group a SCIM directory manages is shown read-only, with its connection: the
 * server refuses an administrator's change to one, and the controls say where the change belongs instead.
 *
 * Creating, renaming, deleting and handing a group over are the bucket's owners' (`can.edit`); changing who
 * is in a group is user management (`can.manageUsers`), open also to those who reach the bucket through a
 * project.
 */
export function BucketGroupsPanel({
	bucketId,
	can,
	users,
	connections,
	refreshKey,
	onChanged,
	onGroups
}: {
	bucketId: string;
	can: Pick<BucketCan, 'edit' | 'manageUsers'>;
	users: PickableUser[];
	connections: ConnectionView[];
	refreshKey: number;
	onChanged: () => void;
	/* The current list, for the user editor's group picker. */
	onGroups?: (groups: GroupView[]) => void;
}) {
	const base = `/admin/api/buckets/${encodeURIComponent(bucketId)}/groups`;
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [groups, setGroups] = useState<GroupView[]>([]);
	const [loading, setLoading] = useState(true);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [createOpen, setCreateOpen] = useState(false);
	const [renaming, setRenaming] = useState<GroupView | null>(null);
	const [membersOf, setMembersOf] = useState<GroupView | null>(null);
	const [assigning, setAssigning] = useState<GroupView | null>(null);
	const [members, setMembers] = useState<MemberView[]>([]);
	const [membersLoading, setMembersLoading] = useState(false);
	const [memberTotal, setMemberTotal] = useState(0);
	const [memberPage, setMemberPage] = useState(1);
	const [adding, setAdding] = useState<string[]>([]);
	const [nameForm] = Form.useForm<{ displayName: string }>();
	const [assignForm] = Form.useForm<{ connectionId: string }>();

	const connectionName = (id: string) =>
		connections.find((c) => c.id === id)?.displayName ?? id;

	const fetchGroups = useCallback(async () => {
		try {
			const result = await request<{ groups: GroupView[] }>('GET', base);
			if (result.ok) {
				setGroups(result.data.groups);
				setLoadError(null);
				onGroups?.(result.data.groups);
			} else {
				setLoadError(result.error.message);
			}
		} finally {
			setLoading(false);
		}
	}, [base, onGroups]);
	useEffect(() => {
		void fetchGroups();
	}, [fetchGroups, refreshKey]);

	const fetchMembers = useCallback(
		async (group: GroupView, page: number) => {
			setMembersLoading(true);
			const result = await request<{
				totalResults: number;
				members: MemberView[];
			}>(
				'GET',
				`${base}/${encodeURIComponent(group.id)}/members?startIndex=${(page - 1) * PAGE + 1}&count=${PAGE}`
			);
			setMembersLoading(false);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			setMembers(result.data.members);
			setMemberTotal(result.data.totalResults);
			setMemberPage(page);
		},
		[base, feedback]
	);

	async function changed() {
		await fetchGroups();
		onChanged();
	}

	async function onCreate({ displayName }: { displayName: string }) {
		const result = await request('POST', base, { displayName });
		if (!result.ok) {
			feedback.failed(result, nameForm);
			return;
		}
		feedback.done(`User group ${displayName} created.`);
		setCreateOpen(false);
		nameForm.resetFields();
		await changed();
	}

	async function onRename({ displayName }: { displayName: string }) {
		if (!renaming) return;
		const result = await request(
			'PATCH',
			`${base}/${encodeURIComponent(renaming.id)}`,
			{ displayName }
		);
		if (!result.ok) {
			feedback.failed(result, nameForm);
			return;
		}
		feedback.done(
			`User group ${renaming.displayName} renamed to ${displayName}.`
		);
		setRenaming(null);
		nameForm.resetFields();
		await changed();
	}

	async function onDelete(group: GroupView) {
		const count = group.memberCount;
		if (
			!(await confirm('userGroup.delete', {
				target: group.displayName,
				consequences: [
					`Its ${String(count)} member${count === 1 ? '' : 's'} lose whatever relying parties grant for it.`,
					'The users themselves are kept.'
				]
			}))
		) {
			return;
		}
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(group.id)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`User group ${group.displayName} deleted.`);
		await changed();
	}

	async function onAddMembers() {
		if (!membersOf || adding.length === 0) return;
		const result = await request(
			'POST',
			`${base}/${encodeURIComponent(membersOf.id)}/members`,
			{ userIds: adding }
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(
			adding.length === 1
				? `User added to ${membersOf.displayName}.`
				: `${String(adding.length)} users added to ${membersOf.displayName}.`
		);
		setAdding([]);
		await fetchMembers(membersOf, memberPage);
		await changed();
	}

	async function onRemoveMember(member: MemberView) {
		if (!membersOf) return;
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(membersOf.id)}/members/${encodeURIComponent(member.id)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(
			`${member.email ?? member.userName ?? 'User'} removed from ${membersOf.displayName}.`
		);
		await fetchMembers(membersOf, memberPage);
		await changed();
	}

	/*
	 * The connection is chosen in the dialog, which closes before the question is asked: a confirmation
	 * stacked on a dialog is a second modal the operator has to read through the first.
	 */
	async function onAssign({ connectionId }: { connectionId: string }) {
		const group = assigning;
		if (!group) return;
		setAssigning(null);
		const connection = connectionName(connectionId);
		if (
			!(await confirm('userGroup.connection.assign', {
				target: group.displayName,
				consequences: [
					`${connection} takes the group over: from then on only the directory can rename it or change its members.`,
					'Every member must already be a user the directory manages.',
					'It cannot be handed back from the console.'
				]
			}))
		) {
			return;
		}
		const result = await request(
			'POST',
			`${base}/${encodeURIComponent(group.id)}/connection`,
			{ connectionId }
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(
			`User group ${group.displayName} handed over to ${connection}.`
		);
		assignForm.resetFields();
		await changed();
	}

	const managedNotice = (group: GroupView) =>
		group.provisionedBy
			? `Managed by ${connectionName(group.provisionedBy)} — change this group in the directory`
			: null;

	function openMembers(group: GroupView) {
		setAdding([]);
		setMembers([]);
		setMembersOf(group);
		void fetchMembers(group, 1);
	}

	function rowActions(group: GroupView): RowAction[] {
		if (!can.edit) return [];
		const notice = managedNotice(group);
		const items: RowAction[] = [
			{
				key: 'rename',
				label: 'Rename…',
				group: 'edit',
				blocked: notice,
				onClick: () => {
					nameForm.setFieldsValue({ displayName: group.displayName });
					setRenaming(group);
				}
			}
		];
		if (!group.provisionedBy && connections.length > 0) {
			items.push({
				key: 'assign',
				label: 'Hand over to connection…',
				group: 'handover',
				onClick: () => {
					assignForm.resetFields();
					setAssigning(group);
				}
			});
		}
		items.push({
			key: 'delete',
			label: 'Delete',
			group: 'danger',
			blocked: notice,
			onClick: () => void onDelete(group)
		});
		return items;
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

	const membersEditable =
		membersOf !== null && !membersOf.provisionedBy && can.manageUsers;

	return (
		<>
			<Space
				style={{
					marginTop: 24,
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
				{createButton}
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
					dataSource={groups}
					pagination={false}
					locale={{
						emptyText: (
							<EmptyState
								purpose="No user groups in this bucket yet. A group's name reaches relying parties in the groups claim of each member's tokens."
								create={createButton}
							/>
						)
					}}
					columns={[
						{
							title: 'Name',
							dataIndex: 'displayName',
							render: (displayName: string, group: GroupView) => (
								<Typography.Link onClick={() => openMembers(group)}>
									{displayName}
								</Typography.Link>
							)
						},
						{ title: 'Members', dataIndex: 'memberCount' },
						{
							title: 'Managed by',
							dataIndex: 'provisionedBy',
							render: (provisionedBy: string | undefined) =>
								provisionedBy ? (
									<Tag color="purple">
										Managed by {connectionName(provisionedBy)}
									</Tag>
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
				title={renaming ? 'Rename user group' : 'New user group'}
				open={createOpen || renaming !== null}
				onCancel={() => {
					setCreateOpen(false);
					setRenaming(null);
				}}
				onOk={() => nameForm.submit()}
				okText={renaming ? 'Rename' : 'Create user group'}
				destroyOnHidden
			>
				<Form<{ displayName: string }>
					form={nameForm}
					layout="vertical"
					onFinish={renaming ? onRename : onCreate}
					scrollToFirstError
				>
					<Form.Item
						name="displayName"
						label="Name"
						tooltip="Unique in this bucket in any letter case. Relying parties receive it in the groups claim, so renaming changes what they see in each member's next token."
						rules={[{ required: true, whitespace: true, max: 256 }]}
					>
						<Input />
					</Form.Item>
				</Form>
			</Modal>

			<Modal
				title={membersOf ? `Members of ${membersOf.displayName}` : 'Members'}
				open={membersOf !== null}
				onCancel={() => setMembersOf(null)}
				footer={null}
				width={720}
				destroyOnHidden
			>
				{membersEditable && (
					<Space.Compact style={{ width: '100%', marginBottom: 12 }}>
						<Select
							mode="multiple"
							style={{ width: '100%' }}
							placeholder="Add users"
							value={adding}
							onChange={setAdding}
							showSearch={{ optionFilterProp: 'label' }}
							options={users.map((u) => ({ label: u.email, value: u._id }))}
						/>
						<Button
							type="primary"
							disabled={adding.length === 0}
							onClick={() => void onAddMembers()}
						>
							Add
						</Button>
					</Space.Compact>
				)}
				<Table<MemberView>
					rowKey="id"
					loading={membersLoading}
					dataSource={members}
					locale={{
						emptyText: (
							<EmptyState purpose="Nobody is in this user group yet." />
						)
					}}
					pagination={{
						current: memberPage,
						pageSize: PAGE,
						total: memberTotal,
						onChange: (page) => membersOf && void fetchMembers(membersOf, page)
					}}
					columns={[
						{ title: 'Email', dataIndex: 'email' },
						{ title: 'Username', dataIndex: 'userName' },
						{
							title: '',
							render: (_: unknown, member: MemberView) => {
								if (!membersEditable) return null;
								const name = member.email ?? member.userName ?? member.id;
								/*
								 * Asked in place rather than in a dialog of its own: this table is already
								 * inside one, and a second modal over it is the stacking the console avoids.
								 */
								return (
									<RowActions
										name={name}
										inline={
											<Popconfirm
												title={REMOVE_MEMBER.title(name)}
												okText={REMOVE_MEMBER.okText}
												onConfirm={() => onRemoveMember(member)}
											>
												<Button size="small">Remove</Button>
											</Popconfirm>
										}
										items={[]}
									/>
								);
							}
						}
					]}
				/>
			</Modal>

			<Modal
				title={
					assigning
						? `Hand ${assigning.displayName} over to a connection`
						: 'Hand over to a connection'
				}
				open={assigning !== null}
				onCancel={() => setAssigning(null)}
				onOk={() => assignForm.submit()}
				okText="Continue"
				destroyOnHidden
			>
				<Typography.Paragraph>
					The directory takes this group over: from then on only it can rename
					the group or change its members. Every member must already be a user
					the directory manages.
				</Typography.Paragraph>
				<Form<{ connectionId: string }>
					form={assignForm}
					layout="vertical"
					onFinish={onAssign}
				>
					<Form.Item
						name="connectionId"
						label="Connection"
						rules={[{ required: true }]}
					>
						<Select
							options={connections.map((c) => ({
								label: c.displayName,
								value: c.id
							}))}
						/>
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
