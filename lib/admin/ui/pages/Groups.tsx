import { useCallback, useEffect, useState } from 'react';
import { Button, Form, Input, Modal, Select, Space, Table, Tag } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { groupLabel } from '../../groups/label.js';
import { PageHeader } from '../frame/PageHeader.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { RowActions } from '../frame/RowActions.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import { meCan, useMe } from '../frame/me.js';

interface GroupMember {
	userId: string;
	role: 'owner' | 'member';
}

interface Group {
	_id: string;
	name: string;
	kind: 'personal' | 'regular' | 'system';
	members: GroupMember[];
}

interface AdminAccount {
	_id: string;
	email: string;
}

function memberUrl(group: Group, userId: string): string {
	return `/admin/api/groups/${encodeURIComponent(group._id)}/members/${encodeURIComponent(userId)}`;
}

function MembersEditor({
	group,
	admins,
	canEdit,
	onClose,
	onChanged,
	onAskFirst
}: {
	group: Group;
	admins: AdminAccount[];
	canEdit: boolean;
	onClose: () => void;
	onChanged: () => Promise<void>;
	/*
	 * Demoting and removing ask first, and a question is never stacked on this modal: the page closes it,
	 * asks, and opens it again on the same group whatever the answer.
	 */
	onAskFirst: (act: 'demote' | 'remove', member: GroupMember) => void;
}) {
	const feedback = useFeedback();
	const [userId, setUserId] = useState<string | undefined>();
	const [role, setRole] = useState<'owner' | 'member'>('member');
	const [busy, setBusy] = useState(false);

	const emailFor = (id: string) =>
		admins.find((a) => a._id === id)?.email ?? id;

	async function promote(member: GroupMember) {
		const result = await request('PATCH', memberUrl(group, member.userId), {
			role: 'owner'
		});
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`${emailFor(member.userId)} made an owner.`);
		await onChanged();
	}

	async function add() {
		setBusy(true);
		try {
			const result = await request(
				'POST',
				`/admin/api/groups/${encodeURIComponent(group._id)}/members`,
				{ userId, role }
			);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			feedback.done(
				`${userId ? emailFor(userId) : 'Member'} added to the group.`
			);
			setUserId(undefined);
			await onChanged();
		} finally {
			setBusy(false);
		}
	}

	return (
		<Modal
			open
			title={`Members of ${groupLabel(group)}`}
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
										<RowActions
											name={emailFor(m.userId)}
											items={[
												m.role === 'owner'
													? {
															key: 'demote',
															label: 'Make member…',
															group: 'state' as const,
															onClick: () => onAskFirst('demote', m)
														}
													: {
															key: 'promote',
															label: 'Make owner',
															group: 'state' as const,
															onClick: () => void promote(m)
														},
												{
													key: 'remove',
													label: 'Remove…',
													group: 'danger' as const,
													onClick: () => onAskFirst('remove', m)
												}
											]}
										/>
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
						showSearch={{ optionFilterProp: 'label' }}
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
						onClick={() => void add()}
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
	const feedback = useFeedback();
	const confirm = useConfirm();
	const { me } = useMe();
	const mayCreate = meCan(me).createGroup;
	const [groups, setGroups] = useState<Group[]>([]);
	const [admins, setAdmins] = useState<AdminAccount[]>([]);
	const [loading, setLoading] = useState(true);
	const [failed, setFailed] = useState<string | null>(null);
	const [open, setOpen] = useState(false);
	/* An id rather than the group, so the open editor shows the members as reloaded after each change. */
	const [editingId, setEditingId] = useState<string | null>(null);
	const [form] = Form.useForm<{ name: string }>();

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchGroups = useCallback(async () => {
		try {
			const result = await request<Group[]>('GET', '/admin/api/groups');
			if (!result.ok) {
				setFailed(result.error.message);
				return;
			}
			setFailed(null);
			setGroups(result.data);
			// Only a super administrator may list administrator accounts, so a project administrator gets
			// an empty picker and adds members by id. Failing quietly is right here: the page still works.
			const who = await request<AdminAccount[]>('GET', '/admin/api/admins');
			if (who.ok) setAdmins(who.data);
		} finally {
			setLoading(false);
		}
	}, []);
	function load() {
		setLoading(true);
		return fetchGroups();
	}

	useEffect(() => {
		void fetchGroups();
	}, [fetchGroups]);

	function isOwner(group: Group): boolean {
		if (isSuperAdmin) return true;
		return group.members.some(
			(m) => m.userId === currentUserId && m.role === 'owner'
		);
	}

	const emailFor = (id: string) =>
		admins.find((a) => a._id === id)?.email ?? id;

	async function onCreate(values: { name: string }) {
		const result = await request('POST', '/admin/api/groups', values);
		if (!result.ok) {
			feedback.failed(result, form);
			return;
		}
		feedback.done(`Group ${values.name} created.`);
		setOpen(false);
		form.resetFields();
		await load();
	}

	async function onDelete(group: Group) {
		const count = group.members.length;
		const yes = await confirm('group.delete', {
			target: groupLabel(group),
			consequences: [
				`Its ${String(count)} ${count === 1 ? 'member loses' : 'members lose'} this membership.`,
				'Refused while it still owns any project or user bucket.'
			]
		});
		if (!yes) return;
		const result = await request(
			'DELETE',
			`/admin/api/groups/${encodeURIComponent(group._id)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`Group ${groupLabel(group)} deleted.`);
		await load();
	}

	async function askFirst(
		group: Group,
		act: 'demote' | 'remove',
		member: GroupMember
	) {
		setEditingId(null);
		const email = emailFor(member.userId);
		const yes =
			act === 'demote'
				? await confirm('group.member.demote', {
						target: email,
						consequences: [
							'They keep access to everything the group owns, but can no longer change its members or delete it.'
						]
					})
				: await confirm('group.member.remove', {
						target: email,
						consequences: [
							'They lose access to everything this group owns, on their next request.'
						]
					});
		if (yes) {
			const result =
				act === 'demote'
					? await request('PATCH', memberUrl(group, member.userId), {
							role: 'member'
						})
					: await request('DELETE', memberUrl(group, member.userId));
			if (result.ok) {
				feedback.done(
					act === 'demote'
						? `${email} made a member.`
						: `${email} removed from the group.`
				);
				await load();
			} else {
				feedback.failed(result);
			}
		}
		setEditingId(group._id);
	}

	const visible = groups.filter((g) => g.kind !== 'personal');
	const editing = groups.find((g) => g._id === editingId) ?? null;

	const newGroup = (
		<Button
			type="primary"
			icon={<PlusOutlined />}
			onClick={() => setOpen(true)}
		>
			New group
		</Button>
	);

	return (
		<>
			<PageHeader
				title="Groups"
				actions={mayCreate ? newGroup : undefined}
			/>
			{failed !== null ? (
				<LoadFailed
					reason={failed}
					onRetry={() => void load()}
				/>
			) : (
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
						emptyText: (
							<EmptyState
								purpose="No groups yet. Create one to share projects and user buckets with colleagues — everything you make on your own stays in your personal scope, which is not listed here."
								create={mayCreate ? newGroup : undefined}
							/>
						)
					}}
					columns={[
						{
							title: 'Name',
							dataIndex: 'name',
							render: (_: string, g: Group) => (
								<Button
									type="link"
									style={{ padding: 0 }}
									onClick={() => setEditingId(g._id)}
								>
									{groupLabel(g)}
								</Button>
							)
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
								<RowActions
									name={groupLabel(g)}
									items={[
										{
											key: 'members',
											label: 'Members…',
											group: 'edit',
											onClick: () => setEditingId(g._id)
										},
										/* Offered only where it can succeed: a personal or system group is never deletable,
										   and a plain member may not delete a group they are in. */
										...(g.kind === 'regular' && isOwner(g)
											? [
													{
														key: 'delete',
														label: 'Delete…',
														group: 'danger' as const,
														onClick: () => void onDelete(g)
													}
												]
											: [])
									]}
								/>
							)
						}
					]}
				/>
			)}
			<Modal
				open={open}
				title="New group"
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
			>
				<Form<{ name: string }>
					form={form}
					layout="vertical"
					scrollToFirstError
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
					 * Keyed on kind, though this table lists no personal group: the reserved holding group
					 * refuses membership edits, and a personal group refuses any new member (specs/075) —
					 * both answered by the server whatever this control offers.
					 */
					canEdit={isOwner(editing) && editing.kind !== 'system'}
					onClose={() => setEditingId(null)}
					onChanged={load}
					onAskFirst={(act, member) => void askFirst(editing, act, member)}
				/>
			)}
		</>
	);
}
