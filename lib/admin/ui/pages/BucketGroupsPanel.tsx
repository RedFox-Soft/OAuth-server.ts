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
	Tooltip,
	Popconfirm,
	message
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { ConnectionView } from './ProvisioningPanel.js';

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

async function failure(res: Response, fallback: string): Promise<string> {
	const body = (await res.json().catch(() => null)) as {
		message?: string;
	} | null;
	return body?.message ?? fallback;
}

/*
 * A bucket's groups of end users. Their names are what relying parties receive in the `groups` claim, so a
 * rename is stated as such. A group a SCIM directory manages is shown read-only, with its connection: the
 * server refuses an administrator's change to one, and the controls say where the change belongs instead.
 */
export function BucketGroupsPanel({
	bucketId,
	users,
	connections,
	refreshKey,
	onChanged,
	onGroups
}: {
	bucketId: string;
	users: PickableUser[];
	connections: ConnectionView[];
	refreshKey: number;
	onChanged: () => void;
	/* The current list, for the user editor's group picker. */
	onGroups?: (groups: GroupView[]) => void;
}) {
	const base = `/admin/api/buckets/${encodeURIComponent(bucketId)}/groups`;
	const [groups, setGroups] = useState<GroupView[]>([]);
	const [loading, setLoading] = useState(true);
	const [createOpen, setCreateOpen] = useState(false);
	const [renaming, setRenaming] = useState<GroupView | null>(null);
	const [membersOf, setMembersOf] = useState<GroupView | null>(null);
	const [assigning, setAssigning] = useState<GroupView | null>(null);
	const [members, setMembers] = useState<MemberView[]>([]);
	const [memberTotal, setMemberTotal] = useState(0);
	const [memberPage, setMemberPage] = useState(1);
	const [adding, setAdding] = useState<string[]>([]);
	const [nameForm] = Form.useForm<{ displayName: string }>();
	const [assignForm] = Form.useForm<{ connectionId: string }>();

	const connectionName = (id: string) =>
		connections.find((c) => c.id === id)?.displayName ?? id;

	const fetchGroups = useCallback(async () => {
		try {
			const res = await fetch(base);
			if (res.ok) {
				const list = ((await res.json()) as { groups: GroupView[] }).groups;
				setGroups(list);
				onGroups?.(list);
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
			const res = await fetch(
				`${base}/${encodeURIComponent(group.id)}/members?startIndex=${(page - 1) * PAGE + 1}&count=${PAGE}`
			);
			if (!res.ok) return;
			const body = (await res.json()) as {
				totalResults: number;
				members: MemberView[];
			};
			setMembers(body.members);
			setMemberTotal(body.totalResults);
			setMemberPage(page);
		},
		[base]
	);

	async function changed() {
		await fetchGroups();
		onChanged();
	}

	async function send(
		method: string,
		path: string,
		body: unknown,
		fallback: string
	): Promise<boolean> {
		const res = await fetch(`${base}${path}`, {
			method,
			headers: body === undefined ? {} : { 'content-type': 'application/json' },
			body: body === undefined ? undefined : JSON.stringify(body)
		});
		if (!res.ok) {
			message.error(await failure(res, fallback));
			return false;
		}
		return true;
	}

	async function onCreate({ displayName }: { displayName: string }) {
		if (await send('POST', '', { displayName }, 'failed to create group')) {
			setCreateOpen(false);
			nameForm.resetFields();
			await changed();
		}
	}

	async function onRename({ displayName }: { displayName: string }) {
		if (!renaming) return;
		if (
			await send(
				'PATCH',
				`/${encodeURIComponent(renaming.id)}`,
				{ displayName },
				'failed to rename group'
			)
		) {
			setRenaming(null);
			nameForm.resetFields();
			await changed();
		}
	}

	async function onDelete(group: GroupView) {
		if (
			await send(
				'DELETE',
				`/${encodeURIComponent(group.id)}`,
				undefined,
				'failed to delete group'
			)
		) {
			await changed();
		}
	}

	async function onAddMembers() {
		if (!membersOf || adding.length === 0) return;
		if (
			await send(
				'POST',
				`/${encodeURIComponent(membersOf.id)}/members`,
				{ userIds: adding },
				'failed to add members'
			)
		) {
			setAdding([]);
			await fetchMembers(membersOf, memberPage);
			await changed();
		}
	}

	async function onRemoveMember(uid: string) {
		if (!membersOf) return;
		if (
			await send(
				'DELETE',
				`/${encodeURIComponent(membersOf.id)}/members/${encodeURIComponent(uid)}`,
				undefined,
				'failed to remove member'
			)
		) {
			await fetchMembers(membersOf, memberPage);
			await changed();
		}
	}

	async function onAssign({ connectionId }: { connectionId: string }) {
		if (!assigning) return;
		if (
			await send(
				'POST',
				`/${encodeURIComponent(assigning.id)}/connection`,
				{ connectionId },
				'failed to assign group'
			)
		) {
			message.success('group assigned — the directory now manages it');
			setAssigning(null);
			assignForm.resetFields();
			await changed();
		}
	}

	const managedNotice = (group: GroupView) =>
		group.provisionedBy
			? `Managed by ${connectionName(group.provisionedBy)} — change this group in the directory`
			: undefined;

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
					Groups
				</Typography.Title>
				<Button
					icon={<PlusOutlined />}
					onClick={() => {
						nameForm.resetFields();
						setCreateOpen(true);
					}}
				>
					New group
				</Button>
			</Space>
			<Table<GroupView>
				rowKey="id"
				loading={loading}
				dataSource={groups}
				pagination={false}
				columns={[
					{ title: 'Name', dataIndex: 'displayName' },
					{ title: 'Members', dataIndex: 'memberCount' },
					{
						title: 'Managed by',
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
						title: 'Actions',
						render: (_: unknown, group: GroupView) => {
							const notice = managedNotice(group);
							return (
								<Space>
									<Button
										size="small"
										onClick={() => {
											setAdding([]);
											setMembersOf(group);
											void fetchMembers(group, 1);
										}}
									>
										Members
									</Button>
									<Tooltip title={notice}>
										<Button
											size="small"
											disabled={notice !== undefined}
											onClick={() => {
												nameForm.setFieldsValue({
													displayName: group.displayName
												});
												setRenaming(group);
											}}
										>
											Rename
										</Button>
									</Tooltip>
									{!group.provisionedBy && connections.length > 0 && (
										<Button
											size="small"
											onClick={() => {
												assignForm.resetFields();
												setAssigning(group);
											}}
										>
											Assign to connection
										</Button>
									)}
									{notice ? (
										<Tooltip title={notice}>
											<Button
												size="small"
												danger
												disabled
											>
												Delete
											</Button>
										</Tooltip>
									) : (
										<Popconfirm
											title="Delete this group?"
											description={`Its ${group.memberCount} member${group.memberCount === 1 ? '' : 's'} lose whatever relying parties grant for it. The users themselves are kept.`}
											okText="Delete group"
											onConfirm={() => onDelete(group)}
										>
											<Button
												size="small"
												danger
											>
												Delete
											</Button>
										</Popconfirm>
									)}
								</Space>
							);
						}
					}
				]}
			/>

			<Modal
				title={renaming ? 'Rename group' : 'New group'}
				open={createOpen || renaming !== null}
				onCancel={() => {
					setCreateOpen(false);
					setRenaming(null);
				}}
				onOk={() => nameForm.submit()}
				destroyOnHidden
			>
				<Form<{ displayName: string }>
					form={nameForm}
					layout="vertical"
					onFinish={renaming ? onRename : onCreate}
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
				{membersOf && !membersOf.provisionedBy && (
					<Space.Compact style={{ width: '100%', marginBottom: 12 }}>
						<Select
							mode="multiple"
							style={{ width: '100%' }}
							placeholder="Add users"
							value={adding}
							onChange={setAdding}
							optionFilterProp="label"
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
					dataSource={members}
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
							render: (_: unknown, member: MemberView) =>
								membersOf && !membersOf.provisionedBy ? (
									<Button
										size="small"
										onClick={() => void onRemoveMember(member.id)}
									>
										Remove
									</Button>
								) : null
						}
					]}
				/>
			</Modal>

			<Modal
				title="Assign group to a connection"
				open={assigning !== null}
				onCancel={() => setAssigning(null)}
				onOk={() => assignForm.submit()}
				okText="Assign"
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
