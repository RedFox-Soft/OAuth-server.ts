import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Flex,
	Form,
	Input,
	Modal,
	Select,
	Skeleton,
	Space,
	Table,
	Tag,
	Typography
} from 'antd';
import { groupLabel } from '../../../groups/label.js';
import { ACTIONS } from '../../frame/actions.js';
import { useConfirm } from '../../frame/confirm.js';
import { useFeedback } from '../../frame/feedback.js';
import { useMe } from '../../frame/me.js';
import { PageHeader } from '../../frame/PageHeader.js';
import { request } from '../../frame/request.js';
import { Link, useNavigate } from '../../frame/router.js';
import { bucketHref } from '../../frame/routes.js';
import { RowActions, type RowAction } from '../../frame/RowActions.js';
import { LoadFailed, NoAccess } from '../../frame/states.js';

type Role = 'owner' | 'member';

interface Member {
	userId: string;
	role: Role;
	email: string | null;
	active: boolean;
}

interface Owned {
	id: string;
	name: string;
}

/* The group as `GET /admin/api/groups/:id` answers it (specs/085). */
interface GroupDetail {
	_id: string;
	name: string;
	kind: 'personal' | 'regular' | 'system';
	members: Member[];
	owns: { buckets: Owned[] };
	can?: Partial<{
		manageMembers: boolean;
		invite: boolean;
		addExisting: boolean;
		rename: boolean;
		delete: boolean;
	}>;
}

interface Invitation {
	_id: string;
	email: string;
	role: Role;
	invitedBy: string;
	expiresAt: string;
	createdAt: string;
}

interface AdminAccount {
	_id: string;
	email: string;
}

function plural(n: number, one: string, many: string): string {
	return `${String(n)} ${n === 1 ? one : many}`;
}

/* "2 buckets" — what membership of this group reaches, with everything those buckets hold. */
function reach(owns: GroupDetail['owns']): string {
	return plural(owns.buckets.length, 'bucket', 'buckets');
}

function OwnedLinks({ owns }: { owns: GroupDetail['owns'] }) {
	const links = [
		...owns.buckets.map((b) => (
			<Link
				key={`b:${b.id}`}
				href={bucketHref(b.id)}
			>
				{b.name}
			</Link>
		))
	];
	return (
		<>
			{links.map((link, i) => (
				<span key={link.key}>
					{i > 0 ? ', ' : ''}
					{link}
				</span>
			))}
		</>
	);
}

function memberUrl(groupId: string, userId: string): string {
	return `/admin/api/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`;
}

/*
 * One administrator group (specs/085): who is in it, who has been invited, what membership reaches, and how it
 * is deleted. Every owner runs it — inviting, promoting and removing — without a super administrator, and
 * every act that changes who reaches what says so in numbers before it happens.
 */
export function AdminGroupPage({ groupId }: { groupId: string }) {
	const { me, reload: reloadMe } = useMe();
	const feedback = useFeedback();
	const confirm = useConfirm();
	const navigate = useNavigate();
	const [group, setGroup] = useState<GroupDetail | null>(null);
	const [invitations, setInvitations] = useState<Invitation[]>([]);
	const [status, setStatus] = useState<number | null>(null);
	const [attempt, setAttempt] = useState(0);
	const [inviting, setInviting] = useState(false);
	const [adding, setAdding] = useState(false);
	const [renaming, setRenaming] = useState(false);
	const [loading, setLoading] = useState(true);

	const base = `/admin/api/groups/${encodeURIComponent(groupId)}`;

	// Every state write follows an await, so the mount effect may call it.
	const load = useCallback(async () => {
		try {
			const [g, inv] = await Promise.all([
				request<GroupDetail>('GET', base),
				request<Invitation[]>('GET', `${base}/invitations`)
			]);
			if (!g.ok) {
				setStatus(g.status);
				return;
			}
			setStatus(null);
			setGroup(g.data);
			setInvitations(inv.ok ? inv.data : []);
		} finally {
			setLoading(false);
		}
	}, [base]);

	useEffect(() => {
		void load();
	}, [load, attempt]);

	if (status !== null) {
		return status === 403 || status === 404 ? (
			<NoAccess
				what="group"
				backHref="/admin/groups"
				backLabel="Back to Groups"
			/>
		) : (
			<LoadFailed onRetry={() => setAttempt((n) => n + 1)} />
		);
	}
	if (!group || (loading && attempt === 0)) return <Skeleton active />;

	// Non-null for the acts below, which are declared after the guard but would not see its narrowing.
	const current: GroupDetail = group;
	const can = group.can ?? {};
	const self = me?.userId ?? null;
	const personal = group.kind === 'personal';
	const own = personal && group.members.some((m) => m.userId === self);
	const label = own ? 'Personal · Only you' : groupLabel(group);
	const owners = group.members.filter((m) => m.role === 'owner').length;
	const nameOf = (m: Pick<Member, 'userId' | 'email'>) => m.email ?? m.userId;
	const ownsNothing = group.owns.buckets.length === 0;

	async function act(
		run: () => ReturnType<typeof request>,
		done: string,
		after?: () => Promise<void>
	) {
		const result = await run();
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(done);
		if (after) await after();
		else await load();
	}

	async function promote(m: Member) {
		const yes = await confirm('group.member.promote', {
			target: nameOf(m),
			consequences: [
				'They can invite and remove administrators, change roles, and delete the group once it owns nothing.',
				`They already reach its ${reach(current.owns)}; that does not change.`
			]
		});
		if (!yes) return;
		await act(
			() => request('PATCH', memberUrl(groupId, m.userId), { role: 'owner' }),
			`${nameOf(m)} is now an owner.`
		);
	}

	async function demote(m: Member) {
		const yes = await confirm('group.member.demote', {
			target: nameOf(m),
			consequences: [
				'They keep access to everything the group owns, but can no longer change its members or delete it.'
			]
		});
		if (!yes) return;
		await act(
			() => request('PATCH', memberUrl(groupId, m.userId), { role: 'member' }),
			`${nameOf(m)} is now a member.`
		);
	}

	async function remove(m: Member) {
		const yes = await confirm('group.member.remove', {
			target: nameOf(m),
			consequences: [
				`They lose access to ${reach(current.owns)} at their next request.`,
				'Their administrator account and their other groups are untouched.'
			]
		});
		if (!yes) return;
		await act(
			() => request('DELETE', memberUrl(groupId, m.userId)),
			`${nameOf(m)} removed from ${label}.`
		);
	}

	async function leave(m: Member) {
		const yes = await confirm('group.member.leave', {
			target: label,
			consequences: [
				`You lose access to ${reach(current.owns)} at once.`,
				'Only an owner of the group can add you back. This page will close.'
			]
		});
		if (!yes) return;
		await act(
			() => request('DELETE', memberUrl(groupId, m.userId)),
			`You left ${label}.`,
			async () => {
				await reloadMe();
				void navigate('/admin/groups', { replace: true });
			}
		);
	}

	async function revoke(inv: Invitation) {
		const yes = await confirm('group.invitation.revoke', {
			target: inv.email,
			consequences: ['The link in their email stops working.']
		});
		if (!yes) return;
		await act(
			() =>
				request('DELETE', `${base}/invitations/${encodeURIComponent(inv._id)}`),
			`Invitation to ${inv.email} revoked.`
		);
	}

	async function deleteGroup() {
		const yes = await confirm('group.delete', {
			target: label,
			consequences: [
				current.members.length === 1
					? `${current.members.map(nameOf).join('')} loses this membership.`
					: `Its ${String(current.members.length)} members lose this membership: ${current.members.map(nameOf).join(', ')}.`,
				'Pending invitations stop working.'
			]
		});
		if (!yes) return;
		await act(
			() => request('DELETE', base),
			`Group ${label} deleted.`,
			async () => {
				await reloadMe();
				void navigate('/admin/groups', { replace: true });
			}
		);
	}

	function actionsFor(m: Member): RowAction[] {
		const lastOwner =
			m.role === 'owner' && owners === 1
				? 'A group must keep at least one owner'
				: null;
		const items: RowAction[] = [];
		if (m.userId === self) {
			items.push({
				key: 'leave',
				label: 'Leave group…',
				group: 'danger',
				blocked: lastOwner,
				onClick: () => void leave(m)
			});
		}
		if (!can.manageMembers) return items;
		items.unshift(
			m.role === 'owner'
				? {
						key: 'demote',
						label: 'Make member…',
						group: 'state',
						blocked: lastOwner,
						onClick: () => void demote(m)
					}
				: {
						key: 'promote',
						label: 'Make owner…',
						group: 'state',
						onClick: () => void promote(m)
					}
		);
		if (m.userId !== self) {
			items.push({
				key: 'remove',
				label: 'Remove…',
				group: 'danger',
				blocked: lastOwner,
				onClick: () => void remove(m)
			});
		}
		return items;
	}

	const ownsCard = (
		<Card title="What this group owns">
			{ownsNothing ? (
				<Typography.Text type="secondary">
					Nothing yet. Buckets created while this group is selected in the
					header belong to it.
				</Typography.Text>
			) : (
				<Flex
					vertical
					gap={8}
				>
					{group.owns.buckets.length > 0 && (
						<div>
							<Typography.Text strong>Buckets: </Typography.Text>
							<OwnedLinks owns={{ buckets: group.owns.buckets }} />
						</div>
					)}
				</Flex>
			)}
		</Card>
	);

	return (
		<>
			<PageHeader
				crumbs={[{ label: 'Groups', href: '/admin/groups' }, { label }]}
				title={label}
				tags={
					group.kind === 'system' ? (
						<Tag>System</Tag>
					) : personal ? (
						<Tag>Personal</Tag>
					) : undefined
				}
				actions={
					can.rename && !personal ? (
						<Button onClick={() => setRenaming(true)}>Rename…</Button>
					) : undefined
				}
			/>
			{personal ? (
				<Flex
					vertical
					gap={16}
				>
					<Alert
						type="info"
						showIcon
						title={
							own
								? 'A personal group can’t be shared. To work with colleagues, create a group and move buckets into it.'
								: 'A personal group belongs to one administrator and can’t be shared.'
						}
						action={
							own ? (
								<Link href="/admin/groups?new=1">
									<Button size="small">New group</Button>
								</Link>
							) : undefined
						}
					/>
					{ownsCard}
				</Flex>
			) : (
				<Flex
					vertical
					gap={16}
				>
					<Card title={`Members (${String(group.members.length)})`}>
						<Table<Member>
							rowKey="userId"
							size="small"
							pagination={false}
							dataSource={[...group.members].sort(
								(a, b) =>
									(a.role === b.role ? 0 : a.role === 'owner' ? -1 : 1) ||
									nameOf(a).localeCompare(nameOf(b))
							)}
							columns={[
								{
									title: 'Administrator',
									key: 'who',
									render: (_: unknown, m: Member) => (
										<Space size={4}>
											{nameOf(m)}
											{m.userId === self && <Tag>You</Tag>}
											{!m.active && <Tag color="default">Inactive</Tag>}
										</Space>
									)
								},
								{
									title: 'Role',
									dataIndex: 'role',
									render: (r: Role) => (
										<Tag color={r === 'owner' ? 'gold' : undefined}>
											{r === 'owner' ? 'Owner' : 'Member'}
										</Tag>
									)
								},
								{
									title: '',
									key: 'actions',
									render: (_: unknown, m: Member) => (
										<RowActions
											name={nameOf(m)}
											items={actionsFor(m)}
										/>
									)
								}
							]}
						/>
					</Card>
					<Card
						title="Pending invitations"
						extra={
							<Space>
								{can.addExisting && (
									<Button onClick={() => setAdding(true)}>
										Add administrator…
									</Button>
								)}
								{can.invite && (
									<Button
										type="primary"
										onClick={() => setInviting(true)}
									>
										Invite administrator…
									</Button>
								)}
							</Space>
						}
					>
						<Table<Invitation>
							rowKey="_id"
							size="small"
							pagination={false}
							dataSource={invitations}
							locale={{ emptyText: 'No invitations waiting.' }}
							columns={[
								{ title: 'Email', dataIndex: 'email' },
								{
									title: 'Role',
									dataIndex: 'role',
									render: (r: Role) => (r === 'owner' ? 'Owner' : 'Member')
								},
								{
									title: 'Invited by',
									dataIndex: 'invitedBy',
									render: (id: string) => {
										const by = group.members.find((m) => m.userId === id);
										return by ? nameOf(by) : 'An administrator';
									}
								},
								{
									title: 'Expires',
									dataIndex: 'expiresAt',
									render: (at: string) => new Date(at).toLocaleString()
								},
								{
									title: '',
									key: 'actions',
									render: (_: unknown, inv: Invitation) =>
										can.invite ? (
											<RowActions
												name={inv.email}
												items={[
													{
														key: 'revoke',
														label: 'Revoke…',
														group: 'danger',
														onClick: () => void revoke(inv)
													}
												]}
											/>
										) : null
								}
							]}
						/>
					</Card>
					{ownsCard}
					{group.kind === 'regular' && can.manageMembers && (
						<Card
							title="Danger zone"
							styles={{ header: { color: 'var(--ant-color-error)' } }}
						>
							<Flex
								justify="space-between"
								align="center"
								wrap
								gap={12}
							>
								<div>
									<Typography.Text strong>Delete group</Typography.Text>
									<br />
									<Typography.Text type="secondary">
										{ownsNothing ? (
											'Its members lose this membership. Nothing else is affected.'
										) : (
											<>
												Move or delete its {reach(group.owns)} first:{' '}
												<OwnedLinks owns={group.owns} />.
											</>
										)}
									</Typography.Text>
								</div>
								<Button
									danger
									disabled={!ownsNothing || can.delete === false}
									onClick={() => void deleteGroup()}
								>
									Delete group…
								</Button>
							</Flex>
						</Card>
					)}
				</Flex>
			)}
			{inviting && (
				<InviteDialog
					groupId={groupId}
					groupLabel={label}
					reachText={reach(group.owns)}
					onClose={() => setInviting(false)}
					onSent={() => {
						setInviting(false);
						void load();
					}}
				/>
			)}
			{adding && (
				<AddExistingDialog
					group={group}
					onClose={() => setAdding(false)}
					onAdded={() => {
						setAdding(false);
						void load();
					}}
				/>
			)}
			{renaming && (
				<RenameDialog
					group={group}
					onClose={() => setRenaming(false)}
					onRenamed={() => {
						setRenaming(false);
						void load();
						void reloadMe();
					}}
				/>
			)}
		</>
	);
}

/*
 * Inviting is the `group.invite` C2 act asked inside its own form: the form states what the invitee will
 * reach, and its danger submit is the consent.
 */
function InviteDialog({
	groupId,
	groupLabel: label,
	reachText,
	onClose,
	onSent
}: {
	groupId: string;
	groupLabel: string;
	reachText: string;
	onClose: () => void;
	onSent: () => void;
}) {
	const [form] = Form.useForm<{ email: string; role: Role }>();
	const role = Form.useWatch('role', form) as Role | undefined;
	const [busy, setBusy] = useState(false);
	const feedback = useFeedback();
	const spec = ACTIONS['group.invite'];

	async function send(values: { email: string; role: Role }) {
		setBusy(true);
		const result = await request(
			'POST',
			`/admin/api/groups/${encodeURIComponent(groupId)}/invitations`,
			values
		);
		setBusy(false);
		if (!result.ok) {
			feedback.failed(result, form);
			return;
		}
		feedback.done(`Invitation sent to ${values.email}.`);
		onSent();
	}

	return (
		<Modal
			open
			title={`Invite an administrator to ${label}`}
			okText={spec.okText}
			okButtonProps={{ danger: true }}
			confirmLoading={busy}
			onOk={() => form.submit()}
			onCancel={onClose}
			destroyOnHidden
		>
			<Form<{ email: string; role: Role }>
				form={form}
				layout="vertical"
				initialValues={{ role: 'member' }}
				onFinish={(values) => void send(values)}
			>
				<Form.Item
					name="email"
					label="Email"
					rules={[{ required: true, type: 'email' }]}
				>
					<Input autoFocus />
				</Form.Item>
				<Form.Item
					name="role"
					label="Role"
				>
					<Select<Role>
						options={[
							{ value: 'member', label: 'Member' },
							{ value: 'owner', label: 'Owner' }
						]}
					/>
				</Form.Item>
			</Form>
			<Alert
				type="warning"
				showIcon
				title={`They'll get access to ${reachText} once they accept.`}
				description={
					role === 'owner'
						? 'As an owner they can also invite and remove administrators and delete the group.'
						: 'The link in the email works once and expires; you can revoke it until it is used.'
				}
			/>
		</Modal>
	);
}

/* A super administrator adds an existing administrator directly, with no invitation. */
function AddExistingDialog({
	group,
	onClose,
	onAdded
}: {
	group: GroupDetail;
	onClose: () => void;
	onAdded: () => void;
}) {
	const [admins, setAdmins] = useState<AdminAccount[] | null>(null);
	const [userId, setUserId] = useState<string | undefined>();
	const [role, setRole] = useState<Role>('member');
	const [busy, setBusy] = useState(false);
	const feedback = useFeedback();

	useEffect(() => {
		void (async () => {
			const result = await request<AdminAccount[]>('GET', '/admin/api/admins');
			setAdmins(result.ok ? result.data : []);
		})();
	}, []);

	async function add() {
		setBusy(true);
		const result = await request(
			'POST',
			`/admin/api/groups/${encodeURIComponent(group._id)}/members`,
			{ userId, role }
		);
		setBusy(false);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		const email =
			admins?.find((a) => a._id === userId)?.email ?? 'Administrator';
		feedback.done(`${email} added to ${groupLabel(group)}.`);
		onAdded();
	}

	return (
		<Modal
			open
			title={`Add an administrator to ${groupLabel(group)}`}
			okText="Add"
			okButtonProps={{ disabled: !userId }}
			confirmLoading={busy}
			onOk={() => void add()}
			onCancel={onClose}
			destroyOnHidden
		>
			<Space
				orientation="vertical"
				style={{ width: '100%' }}
			>
				<Select<string>
					placeholder="Administrator"
					style={{ width: '100%' }}
					loading={admins === null}
					value={userId}
					onChange={setUserId}
					showSearch={{ optionFilterProp: 'label' }}
					options={(admins ?? [])
						.filter((a) => !group.members.some((m) => m.userId === a._id))
						.map((a) => ({ value: a._id, label: a.email }))}
				/>
				<Select<Role>
					value={role}
					onChange={setRole}
					options={[
						{ value: 'member', label: 'Member' },
						{ value: 'owner', label: 'Owner' }
					]}
				/>
				<Typography.Text type="secondary">
					They get access to everything this group owns at once.
				</Typography.Text>
			</Space>
		</Modal>
	);
}

function RenameDialog({
	group,
	onClose,
	onRenamed
}: {
	group: GroupDetail;
	onClose: () => void;
	onRenamed: () => void;
}) {
	const [form] = Form.useForm<{ name: string }>();
	const [busy, setBusy] = useState(false);
	const feedback = useFeedback();

	async function save(values: { name: string }) {
		setBusy(true);
		const result = await request(
			'PATCH',
			`/admin/api/groups/${encodeURIComponent(group._id)}`,
			values
		);
		setBusy(false);
		if (!result.ok) {
			feedback.failed(result, form);
			return;
		}
		feedback.done(`Group renamed to “${values.name}”.`);
		onRenamed();
	}

	return (
		<Modal
			open
			title="Rename group"
			okText="Save"
			confirmLoading={busy}
			onOk={() => form.submit()}
			onCancel={onClose}
			destroyOnHidden
		>
			<Form<{ name: string }>
				form={form}
				layout="vertical"
				initialValues={{ name: group.name }}
				onFinish={(values) => void save(values)}
			>
				<Form.Item
					name="name"
					label="Name"
					rules={[{ required: true, whitespace: true }]}
				>
					<Input autoFocus />
				</Form.Item>
			</Form>
		</Modal>
	);
}
