import { useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Form,
	Input,
	Modal,
	Popconfirm,
	Select,
	Space,
	Table,
	Tag,
	message
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { groupLabel } from '../groupLabel.js';

interface GroupMember {
	userId: string;
	role: 'owner' | 'member';
}

interface Group {
	_id: string;
	name: string;
	kind: 'personal' | 'regular' | 'system';
	members: GroupMember[];
	needsReview: boolean;
}

interface AdminAccount {
	_id: string;
	email: string;
}

/*
 * Reads the refusal the admin plane actually sent rather than showing a generic failure. Every admin
 * route answers `{ error, message }`, and the message is the part worth showing: "a group must keep at
 * least one owner" tells an operator what to do, where "request failed" does not.
 */
async function refusal(res: Response): Promise<string> {
	try {
		const body = (await res.json()) as { message?: string };
		return body.message ?? `request failed (${res.status})`;
	} catch {
		return `request failed (${res.status})`;
	}
}

function MembersEditor({
	group,
	admins,
	canEdit,
	onClose,
	onChanged
}: {
	group: Group;
	admins: AdminAccount[];
	canEdit: boolean;
	onClose: () => void;
	onChanged: () => void;
}) {
	const [userId, setUserId] = useState<string | undefined>();
	const [role, setRole] = useState<'owner' | 'member'>('member');
	const [busy, setBusy] = useState(false);

	const emailFor = (id: string) =>
		admins.find((a) => a._id === id)?.email ?? id;

	async function send(url: string, init: RequestInit) {
		setBusy(true);
		try {
			const res = await fetch(url, init);
			if (!res.ok) {
				message.error(await refusal(res));
				return;
			}
			onChanged();
		} finally {
			setBusy(false);
		}
	}

	return (
		<Modal
			open
			title={`Members of ${group.name}`}
			onCancel={onClose}
			footer={null}
		>
			<Table<GroupMember>
				rowKey="userId"
				size="small"
				pagination={false}
				dataSource={group.members}
				columns={[
					{
						title: 'Administrator',
						dataIndex: 'userId',
						render: (id: string) => emailFor(id)
					},
					{
						title: 'Membership',
						dataIndex: 'role',
						render: (r: string) => (
							<Tag color={r === 'owner' ? 'gold' : undefined}>{r}</Tag>
						)
					},
					...(canEdit
						? [
								{
									title: '',
									key: 'actions',
									render: (_: unknown, m: GroupMember) => (
										<Space>
											<a
												onClick={() =>
													send(
														`/admin/api/groups/${encodeURIComponent(group._id)}/members/${encodeURIComponent(m.userId)}`,
														{
															method: 'PATCH',
															headers: {
																'content-type': 'application/json'
															},
															body: JSON.stringify({
																role: m.role === 'owner' ? 'member' : 'owner'
															})
														}
													)
												}
											>
												{m.role === 'owner' ? 'Demote' : 'Promote'}
											</a>
											<Popconfirm
												title="Remove from group?"
												description="They lose access to everything this group owns, on their next request."
												onConfirm={() =>
													send(
														`/admin/api/groups/${encodeURIComponent(group._id)}/members/${encodeURIComponent(m.userId)}`,
														{ method: 'DELETE' }
													)
												}
											>
												<a>Remove</a>
											</Popconfirm>
										</Space>
									)
								}
							]
						: [])
				]}
			/>
			{canEdit && (
				<Space style={{ marginTop: 16 }}>
					<Select
						placeholder="Administrator"
						style={{ minWidth: 240 }}
						value={userId}
						onChange={setUserId}
						showSearch
						optionFilterProp="label"
						options={admins
							.filter((a) => !group.members.some((m) => m.userId === a._id))
							.map((a) => ({ value: a._id, label: a.email }))}
					/>
					<Select
						value={role}
						onChange={setRole}
						options={[
							{ value: 'member', label: 'member' },
							{ value: 'owner', label: 'owner' }
						]}
					/>
					<Button
						loading={busy}
						disabled={!userId}
						onClick={() =>
							send(
								`/admin/api/groups/${encodeURIComponent(group._id)}/members`,
								{
									method: 'POST',
									headers: { 'content-type': 'application/json' },
									body: JSON.stringify({ userId, role })
								}
							)
						}
					>
						Add
					</Button>
				</Space>
			)}
		</Modal>
	);
}

export function Groups({
	isSuperAdmin,
	currentUserId
}: {
	isSuperAdmin: boolean;
	currentUserId: string | null;
}) {
	const [groups, setGroups] = useState<Group[]>([]);
	const [admins, setAdmins] = useState<AdminAccount[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [editing, setEditing] = useState<Group | null>(null);
	const [form] = Form.useForm<{ name: string }>();

	async function load() {
		setLoading(true);
		try {
			const res = await fetch('/admin/api/groups');
			if (res.ok) setGroups((await res.json()) as Group[]);
			// Only a super administrator may list administrator accounts, so a project administrator gets
			// an empty picker and adds members by id. Failing quietly is right here: the page still works.
			const who = await fetch('/admin/api/admins');
			if (who.ok) setAdmins((await who.json()) as AdminAccount[]);
		} finally {
			setLoading(false);
		}
	}

	useEffect(() => {
		load();
	}, []);

	function isOwner(group: Group): boolean {
		if (isSuperAdmin) return true;
		return group.members.some(
			(m) => m.userId === currentUserId && m.role === 'owner'
		);
	}

	async function onCreate(values: { name: string }) {
		const res = await fetch('/admin/api/groups', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(values)
		});
		if (!res.ok) {
			message.error(await refusal(res));
			return;
		}
		setOpen(false);
		form.resetFields();
		await load();
	}

	async function onDelete(group: Group) {
		const res = await fetch(
			`/admin/api/groups/${encodeURIComponent(group._id)}`,
			{ method: 'DELETE' }
		);
		if (!res.ok) {
			message.error(await refusal(res));
			return;
		}
		await load();
	}

	const visible = groups.filter((g) => g.kind !== 'personal');
	const needingReview = visible.filter((g) => g.needsReview);

	return (
		<>
			{needingReview.length > 0 && (
				<Alert
					type="warning"
					showIcon
					style={{ marginBottom: 16 }}
					message={`${needingReview.length} group(s) were generated by the ownership migration`}
					description="Each was built from a set of administrators who managed the same containers before groups existed. Confirm the grouping is a real team, and split or rename it if not."
				/>
			)}
			<div style={{ marginBottom: 16, textAlign: 'right' }}>
				<Button
					type="primary"
					icon={<PlusOutlined />}
					onClick={() => setOpen(true)}
				>
					New group
				</Button>
			</div>
			<Table<Group>
				rowKey="_id"
				loading={loading}
				/*
				 * Personal groups are left out: this page is about the teams work is shared with, and a
				 * personal group is not one — it is the scope an administrator's own work already sits in,
				 * reachable from the scope switcher. Listed, they said nothing useful to their own owner and
				 * gave a super administrator one indistinguishable row per administrator on the instance.
				 *
				 * Filtered here rather than in `GET /admin/api/groups`, which is also the MCP `group_list`
				 * tool and the answer to "which groups does this account belong to". Hiding a row is a
				 * decision about this table, not about what the account may see.
				 */
				dataSource={visible}
				locale={{
					emptyText:
						'No groups yet. Create one to share projects and user buckets with colleagues — everything you make on your own stays in your personal scope, which is not listed here.'
				}}
				columns={[
					{
						title: 'Name',
						dataIndex: 'name',
						render: (_: string, g: Group) => groupLabel(g)
					},
					{
						title: 'Kind',
						dataIndex: 'kind',
						render: (kind: string) => <Tag>{kind}</Tag>
					},
					{
						title: 'Members',
						dataIndex: 'members',
						render: (members: GroupMember[]) => members.length
					},
					{
						title: '',
						key: 'actions',
						render: (_: unknown, g: Group) => (
							<Space>
								<a onClick={() => setEditing(g)}>Members</a>
								{/* Offered only where it can succeed: a personal or system group is never deletable,
								    and a plain member may not delete a group they are in. */}
								{g.kind === 'regular' && isOwner(g) && (
									<Popconfirm
										title="Delete this group?"
										description="Refused while it still owns any project or user bucket."
										onConfirm={() => onDelete(g)}
									>
										<a>Delete</a>
									</Popconfirm>
								)}
							</Space>
						)
					}
				]}
			/>
			<Modal
				open={open}
				title="New group"
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
			>
				<Form<{ name: string }>
					form={form}
					layout="vertical"
					onFinish={onCreate}
				>
					<Form.Item
						label="Name"
						name="name"
						rules={[{ required: true }]}
						extra="Usually a company or team name. You become its first owner."
					>
						<Input />
					</Form.Item>
				</Form>
			</Modal>
			{editing && (
				<MembersEditor
					group={editing}
					admins={admins}
					/*
					 * Kept keyed on kind rather than assuming a regular group, even though this table no
					 * longer lists personal ones: a personal group is still shareable through the API, and
					 * what refuses membership edits is being the reserved holding group, nothing else.
					 */
					canEdit={isOwner(editing) && editing.kind !== 'system'}
					onClose={() => setEditing(null)}
					onChanged={async () => {
						setEditing(null);
						await load();
					}}
				/>
			)}
		</>
	);
}
