import { useCallback, useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	Select,
	Switch,
	Space,
	Tag,
	Typography,
	Tooltip,
	Popconfirm,
	message
} from 'antd';
import { ArrowLeftOutlined, PlusOutlined } from '@ant-design/icons';
import type { UserBucket, User } from '../../../adapters/types.js';
import { FederationPanel } from './FederationPanel.js';
import { BucketKeysPanel } from './BucketKeysPanel.js';
import { UserIdentities } from './UserIdentities.js';
import { ProvisioningPanel, type ConnectionView } from './ProvisioningPanel.js';
import { BucketGroupsPanel, type GroupView } from './BucketGroupsPanel.js';

/*
 * What the API actually returns, which is not the stored record: `presentUser` removes the password
 * hash and the authenticator secret, and substitutes the two derived facts an operator may see. Typed
 * from that shape rather than from `User` so the console cannot accidentally reference a field the
 * server does not send.
 */
type EndUser = Omit<User, 'password' | 'totp'> & {
	totpEnrolled: boolean;
	totpEnrolledAt: string | null;
	groups?: { id: string; displayName: string; provisionedBy?: string }[];
};

interface CreateValues {
	email: string;
	password: string;
	claimsText?: string;
}

interface AssignValues {
	connectionId: string;
	userName?: string;
	externalId?: string;
}

interface EditValues {
	active: boolean;
	claimsText?: string;
	/* The groups administrators keep that this user is in; a directory's groups are not edited here. */
	groupIds?: string[];
}

/*
 * The claims an account releases, edited as JSON text. Parsed here only to refuse what is not an object
 * before a round trip; which names are allowed is the server's rule, and its refusal is shown as is.
 */
function parseClaims(text: string | undefined): Record<string, unknown> {
	const trimmed = text?.trim();
	if (!trimmed) return {};
	const value: unknown = JSON.parse(trimmed);
	if (typeof value !== 'object' || value === null || Array.isArray(value)) {
		throw new TypeError('claims must be a JSON object');
	}
	return value as Record<string, unknown>;
}

function ClaimsField() {
	return (
		<Form.Item
			name="claimsText"
			label="Claims"
			tooltip='JSON, e.g. {"name":"Ada Lovelace","locale":"en-GB"}. Released to a client only when the claims setting names them under a scope the client was granted. sub, email and email_verified come from the account itself and cannot be set here.'
			rules={[
				{
					validator: async (_rule, text: string | undefined) => {
						parseClaims(text);
					}
				}
			]}
		>
			<Input.TextArea
				rows={4}
				spellCheck={false}
				placeholder='{"name":"Ada Lovelace"}'
			/>
		</Form.Item>
	);
}

export function BucketDetail({
	bucketId,
	onBack
}: {
	bucketId: string;
	onBack: () => void;
}) {
	const base = `/admin/api/buckets/${encodeURIComponent(bucketId)}`;
	const [bucket, setBucket] = useState<UserBucket | null>(null);
	const [rows, setRows] = useState<EndUser[]>([]);
	const [loading, setLoading] = useState(true);
	const [createOpen, setCreateOpen] = useState(false);
	const [editOpen, setEditOpen] = useState(false);
	const [pwUser, setPwUser] = useState<EndUser | null>(null);
	const [identitiesUser, setIdentitiesUser] = useState<EndUser | null>(null);
	const [assignUser, setAssignUser] = useState<EndUser | null>(null);
	const [connections, setConnections] = useState<ConnectionView[]>([]);
	/*
	 * The two panels below each fetch their own list, and each changes what the other shows: a connection
	 * closes its provider to just-in-time creation, and a provider's state is a connection's warning. A
	 * bumped key is how one tells the other to look again without either holding the other's state.
	 */
	const [federationKey, setFederationKey] = useState(0);
	const [provisioningKey, setProvisioningKey] = useState(0);
	const [groupsKey, setGroupsKey] = useState(0);
	const [bucketGroups, setBucketGroups] = useState<GroupView[]>([]);
	const [bucketEditOpen, setBucketEditOpen] = useState(false);
	const [saving, setSaving] = useState(false);
	const [createForm] = Form.useForm<CreateValues>();
	const [editForm] = Form.useForm<EditValues>();
	const [pwForm] = Form.useForm<{ password: string }>();
	const [assignForm] = Form.useForm<AssignValues>();
	const [bucketForm] = Form.useForm<{
		name: string;
		passwordLogin?: boolean;
		registrationOpen?: boolean;
		emailVerificationRequired?: boolean;
		verificationMethod?: 'link' | 'code';
		totpRequired?: boolean;
	}>();

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchBucket = useCallback(async () => {
		try {
			const [b, u] = await Promise.all([fetch(base), fetch(`${base}/users`)]);
			if (b.ok) setBucket((await b.json()) as UserBucket);
			if (u.ok) setRows((await u.json()) as EndUser[]);
		} finally {
			setLoading(false);
		}
	}, [base]);
	function load() {
		setLoading(true);
		return fetchBucket();
	}
	useEffect(() => {
		void fetchBucket();
	}, [fetchBucket]);

	async function post(path: string, bodyObj: unknown, okMsg: string) {
		const res = await fetch(`${base}${path}`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(bodyObj)
		});
		const body = (await res.json().catch(() => null)) as {
			message?: string;
		} | null;
		if (!res.ok) {
			message.error(body?.message || `failed: ${okMsg}`);
			return false;
		}
		return true;
	}

	async function onCreate({ claimsText, ...values }: CreateValues) {
		const claims = parseClaims(claimsText);
		setSaving(true);
		try {
			const body = Object.keys(claims).length ? { ...values, claims } : values;
			if (await post('/users', body, 'create user')) {
				setCreateOpen(false);
				createForm.resetFields();
				await load();
			}
		} finally {
			setSaving(false);
		}
	}

	async function onEdit({ claimsText, groupIds, ...values }: EditValues) {
		if (!editUserId) return;
		/*
		 * Membership is changed through the group's own routes, one per group that changed, so a change made
		 * here and one made from the group read the same in the audit trail.
		 */
		const kept = new Set(
			bucketGroups.filter((g) => !g.provisionedBy).map((g) => g.id)
		);
		const before = new Set(
			(rows.find((r) => r._id === editUserId)?.groups ?? [])
				.map((g) => g.id)
				.filter((id) => kept.has(id))
		);
		const after = new Set(groupIds ?? []);
		const groupsBase = `${base}/groups`;
		for (const gid of after) {
			if (before.has(gid)) continue;
			const res = await fetch(
				`${groupsBase}/${encodeURIComponent(gid)}/members`,
				{
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ userIds: [editUserId] })
				}
			);
			if (!res.ok) message.error('failed to add the user to a group');
		}
		for (const gid of before) {
			if (after.has(gid)) continue;
			const res = await fetch(
				`${groupsBase}/${encodeURIComponent(gid)}/members/${encodeURIComponent(editUserId)}`,
				{ method: 'DELETE' }
			);
			if (!res.ok) message.error('failed to remove the user from a group');
		}
		setGroupsKey((k) => k + 1);
		// An emptied field clears the claims: an edit replaces the account's whole set.
		const res = await fetch(`${base}/users/${editUserId}`, {
			method: 'PATCH',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ ...values, claims: parseClaims(claimsText) })
		});
		if (!res.ok) {
			const detail = (await res.json().catch(() => null)) as {
				message?: string;
			} | null;
			message.error(detail?.message || 'failed to update user');
			return;
		}
		setEditOpen(false);
		await load();
	}

	const [editUserId, setEditUserId] = useState<string | null>(null);

	async function onResetPassword(values: { password: string }) {
		if (!pwUser) return;
		if (await post(`/users/${pwUser._id}/password`, values, 'reset password')) {
			message.success('password reset');
			setPwUser(null);
			pwForm.resetFields();
		}
	}

	async function onAssign(values: AssignValues) {
		if (!assignUser) return;
		const userName = values.userName?.trim();
		const externalId = values.externalId?.trim();
		const body = {
			connectionId: values.connectionId,
			...(userName ? { userName } : {}),
			...(externalId ? { externalId } : {})
		};
		setSaving(true);
		try {
			if (
				await post(
					`/users/${encodeURIComponent(assignUser._id)}/connection`,
					body,
					'assign to connection'
				)
			) {
				message.success('user assigned — the directory now manages them');
				setAssignUser(null);
				assignForm.resetFields();
				setProvisioningKey((k) => k + 1);
				await load();
			}
		} finally {
			setSaving(false);
		}
	}

	async function onDelete(uid: string) {
		const res = await fetch(`${base}/users/${uid}`, { method: 'DELETE' });
		if (!res.ok) {
			message.error('failed to delete user');
			return;
		}
		await load();
	}

	async function onSignOut(uid: string) {
		const res = await fetch(`${base}/users/${uid}/sign-out`, {
			method: 'POST'
		});
		if (!res.ok) {
			// The server's own reason: a partial sweep names the areas whose records survived.
			const detail = (await res.json().catch(() => null)) as {
				message?: string;
			} | null;
			message.error(detail?.message ?? 'failed to sign the user out');
			return;
		}
		message.success('signed out everywhere — they can sign in again');
		await load();
	}

	async function onClearTotp(uid: string) {
		const res = await fetch(`${base}/users/${uid}/totp`, { method: 'DELETE' });
		if (!res.ok) {
			// The server's own reason where it gives one — a partial session sweep says which areas
			// survived, and replacing that with a generic sentence would hide the half that matters.
			const detail = (await res.json().catch(() => null)) as {
				message?: string;
			} | null;
			message.error(detail?.message ?? 'failed to clear the authenticator');
			return;
		}
		message.success(
			'authenticator cleared — they will set up a new one at their next sign-in'
		);
		await load();
	}

	async function onSaveBucket(values: {
		name: string;
		passwordLogin?: boolean;
		registrationOpen?: boolean;
		emailVerificationRequired?: boolean;
		verificationMethod?: 'link' | 'code';
		totpRequired?: boolean;
	}) {
		const res = await fetch(base, {
			method: 'PATCH',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(values)
		});
		if (!res.ok) {
			/*
			 * The server's own reason, not a generic sentence. Turning password sign-in off on a bucket with no
			 * enabled provider is refused with an explanation of what to do first, and replacing that with
			 * "failed to update bucket" would leave an operator guessing at a rule the server already stated.
			 */
			const detail = (await res.json().catch(() => null)) as {
				message?: string;
			} | null;
			message.error(detail?.message ?? 'failed to update bucket');
			return;
		}
		setBucketEditOpen(false);
		await load();
	}

	return (
		<>
			<Space
				style={{
					marginBottom: 16,
					justifyContent: 'space-between',
					width: '100%'
				}}
			>
				<Button
					icon={<ArrowLeftOutlined />}
					onClick={onBack}
				>
					Back
				</Button>
				<Typography.Title
					level={4}
					style={{ margin: 0 }}
				>
					{bucket?.name ?? bucketId} — users
				</Typography.Title>
				<Space>
					<Button
						onClick={() => {
							bucketForm.setFieldsValue({
								passwordLogin: bucket?.passwordLogin !== false,
								name: bucket?.name ?? '',
								registrationOpen: bucket?.registrationOpen ?? true,
								emailVerificationRequired:
									bucket?.emailVerificationRequired ?? false,
								verificationMethod: bucket?.verificationMethod ?? 'link',
								totpRequired: bucket?.totpRequired ?? false
							});
							setBucketEditOpen(true);
						}}
					>
						Edit bucket
					</Button>
					<Button
						type="primary"
						icon={<PlusOutlined />}
						onClick={() => setCreateOpen(true)}
					>
						New user
					</Button>
				</Space>
			</Space>
			<Table<EndUser>
				rowKey="_id"
				loading={loading}
				dataSource={rows}
				columns={[
					{ title: 'Email', dataIndex: 'email' },
					{
						title: 'Groups',
						dataIndex: 'groups',
						render: (groups: EndUser['groups']) =>
							(groups ?? []).map((g) => (
								<Tag
									key={g.id}
									color={g.provisionedBy ? 'purple' : undefined}
								>
									{g.displayName}
								</Tag>
							))
					},
					{
						title: 'Active',
						dataIndex: 'active',
						render: (a: boolean) =>
							a ? <Tag color="green">active</Tag> : <Tag>inactive</Tag>
					},
					{
						title: 'Verified',
						dataIndex: 'verified',
						render: (v: boolean) => (v ? 'yes' : 'no')
					},
					{
						// Whether there is an authenticator, and since when. Never the secret behind it —
						// the server does not send it, to any role.
						title: 'Authenticator',
						dataIndex: 'totpEnrolled',
						render: (enrolled: boolean, row: EndUser) =>
							enrolled ? (
								<Tooltip
									title={
										row.totpEnrolledAt
											? `Enrolled ${new Date(row.totpEnrolledAt).toLocaleString()}`
											: 'Enrolled'
									}
								>
									<Tag color="green">enrolled</Tag>
								</Tooltip>
							) : (
								<Tag>none</Tag>
							)
					},
					{
						/*
						 * Who owns the record. A connection's display name where it is known; its id
						 * otherwise, because a stale list must not make a managed user look local.
						 */
						title: 'Managed by',
						dataIndex: 'provisionedBy',
						render: (provisionedBy: string | undefined) =>
							provisionedBy ? (
								<Tag color="purple">
									{connections.find((c) => c.id === provisionedBy)
										?.displayName ?? provisionedBy}
								</Tag>
							) : (
								<Typography.Text type="secondary">local</Typography.Text>
							)
					},
					{
						title: 'Actions',
						render: (_: unknown, row: EndUser) => {
							/*
							 * The directory owns a provisioned record, and the server refuses these three for
							 * one. Disabled rather than hidden, so the operator learns where the change belongs
							 * instead of wondering why the buttons vanished.
							 */
							const managedNotice = row.provisionedBy
								? `Managed by ${
										connections.find((c) => c.id === row.provisionedBy)
											?.displayName ?? row.provisionedBy
									} — change this user in the directory`
								: undefined;
							return (
								<Space>
									<Tooltip title={managedNotice}>
										<Button
											size="small"
											disabled={managedNotice !== undefined}
											onClick={() => {
												setEditUserId(row._id);
												editForm.setFieldsValue({
													groupIds: (row.groups ?? [])
														.filter((g) => !g.provisionedBy)
														.map((g) => g.id),
													active: row.active,
													claimsText: row.claims
														? JSON.stringify(row.claims, null, 2)
														: ''
												});
												setEditOpen(true);
											}}
										>
											Edit
										</Button>
									</Tooltip>
									<Tooltip title={managedNotice}>
										<Button
											size="small"
											disabled={managedNotice !== undefined}
											onClick={() => setPwUser(row)}
										>
											Reset password
										</Button>
									</Tooltip>
									<Button
										size="small"
										onClick={() => setIdentitiesUser(row)}
									>
										Identities
									</Button>
									{!row.provisionedBy && connections.length > 0 && (
										<Button
											size="small"
											onClick={() => {
												assignForm.resetFields();
												setAssignUser(row);
											}}
										>
											Assign to connection
										</Button>
									)}
									{/* Offered only where there is something to clear, and stating the two
								    consequences an operator cannot see from here: the old codes stop working,
								    and the person is signed out everywhere. */}
									{/* Allowed on a provisioned user too: it ends access and edits nothing the connection owns. */}
									<Popconfirm
										title="Sign this user out everywhere?"
										description="Every session and token ends at once and relying parties are told. The account stays active: they can sign in again, and will be asked to consent again."
										okText="Sign out everywhere"
										onConfirm={() => onSignOut(row._id)}
									>
										<Button size="small">Sign out everywhere</Button>
									</Popconfirm>
									{row.totpEnrolled && (
										<Popconfirm
											title="Clear this authenticator?"
											description="Their current authenticator stops working immediately and they are signed out everywhere. They set up a new one at their next sign-in."
											okText="Clear and sign out"
											onConfirm={() => onClearTotp(row._id)}
										>
											<Button size="small">Clear authenticator</Button>
										</Popconfirm>
									)}
									{/* The consequence, stated: deleting an account also ends the sessions and tokens
								    it is currently using, which is the half an operator cannot see from here. */}
									{managedNotice ? (
										<Tooltip title={managedNotice}>
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
											title="Delete this user?"
											description="Their sign-in sessions, consents and every issued token are destroyed immediately — they are signed out everywhere."
											okText="Delete and sign out"
											onConfirm={() => onDelete(row._id)}
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

			<BucketGroupsPanel
				bucketId={bucketId}
				users={rows}
				connections={connections}
				refreshKey={groupsKey}
				onGroups={setBucketGroups}
				onChanged={() => void load()}
			/>

			<FederationPanel
				key={federationKey}
				bucketId={bucketId}
				// The bucket's own settings depend on this list, so a change here refreshes what the
				// password-sign-in switch is validated against.
				onChanged={() => {
					void load();
					setProvisioningKey((k) => k + 1);
				}}
			/>

			<ProvisioningPanel
				bucketId={bucketId}
				refreshKey={provisioningKey}
				onConnections={setConnections}
				onChanged={(event) => {
					void load();
					if (event === 'created') setFederationKey((k) => k + 1);
				}}
			/>

			<BucketKeysPanel bucketId={bucketId} />

			<UserIdentities
				bucketId={bucketId}
				user={identitiesUser}
				onClose={() => setIdentitiesUser(null)}
			/>

			<Modal
				title="New user"
				open={createOpen}
				onCancel={() => setCreateOpen(false)}
				onOk={() => createForm.submit()}
				confirmLoading={saving}
				destroyOnHidden
			>
				<Form<CreateValues>
					form={createForm}
					layout="vertical"
					onFinish={onCreate}
				>
					{/* An address beside a password reads as a sign-in form to a browser, which filled both
					    with the administrator's own credentials. See the same pair in Admins.tsx. */}
					<Form.Item
						name="email"
						label="Email"
						rules={[{ required: true, type: 'email' }]}
					>
						<Input autoComplete="off" />
					</Form.Item>
					<Form.Item
						name="password"
						label="Initial password"
						rules={[{ required: true, min: 8 }]}
					>
						<Input.Password
							autoComplete="new-password"
							placeholder="at least 8 characters"
						/>
					</Form.Item>
					<ClaimsField />
				</Form>
			</Modal>

			<Modal
				title={assignUser ? `Assign ${assignUser.email} to a connection` : ''}
				open={assignUser !== null}
				onCancel={() => setAssignUser(null)}
				onOk={() => assignForm.submit()}
				confirmLoading={saving}
				destroyOnHidden
			>
				<Typography.Paragraph type="secondary">
					The directory then owns this account: it is read-only here except for
					a local lock. Give the names the directory knows this person by, so
					its next sync matches them instead of creating someone new.
				</Typography.Paragraph>
				<Form<AssignValues>
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
					<Form.Item
						name="userName"
						label="userName"
					>
						<Input autoComplete="off" />
					</Form.Item>
					<Form.Item
						name="externalId"
						label="externalId"
						dependencies={['userName']}
						rules={[
							({ getFieldValue }) => ({
								validator: async (_rule, value: string | undefined) => {
									const userName = (
										getFieldValue('userName') as string | undefined
									)?.trim();
									if (!userName && !value?.trim()) {
										throw new Error('give a userName, an externalId, or both');
									}
								}
							})
						]}
					>
						<Input autoComplete="off" />
					</Form.Item>
				</Form>
			</Modal>

			<Modal
				title="Edit user"
				open={editOpen}
				onCancel={() => setEditOpen(false)}
				onOk={() => editForm.submit()}
				destroyOnHidden
			>
				<Form
					form={editForm}
					layout="vertical"
					onFinish={onEdit}
				>
					<Form.Item
						name="groupIds"
						label="Groups"
						tooltip="Groups administrators keep. A directory's groups are changed in the directory."
					>
						<Select
							mode="multiple"
							showSearch={{ optionFilterProp: 'label' }}
							options={bucketGroups
								.filter((g) => !g.provisionedBy)
								.map((g) => ({ label: g.displayName, value: g.id }))}
						/>
					</Form.Item>
					<Form.Item
						name="active"
						label="Active"
						valuePropName="checked"
					>
						<Switch />
					</Form.Item>
					<ClaimsField />
				</Form>
			</Modal>

			<Modal
				title="Reset password"
				open={pwUser !== null}
				onCancel={() => setPwUser(null)}
				onOk={() => pwForm.submit()}
				destroyOnHidden
			>
				<Form
					form={pwForm}
					layout="vertical"
					onFinish={onResetPassword}
				>
					<Form.Item
						name="password"
						label="New password"
						rules={[{ required: true, min: 8 }]}
					>
						{/* This sets somebody else's password, so a stored one is never the right value. */}
						<Input.Password autoComplete="new-password" />
					</Form.Item>
				</Form>
			</Modal>

			<Modal
				title="Edit bucket"
				open={bucketEditOpen}
				onCancel={() => setBucketEditOpen(false)}
				onOk={() => bucketForm.submit()}
				destroyOnHidden
			>
				<Form
					form={bucketForm}
					layout="vertical"
					onFinish={onSaveBucket}
				>
					<Form.Item
						name="name"
						label="Name"
						rules={[{ required: true }]}
					>
						<Input />
					</Form.Item>
					<Form.Item
						name="passwordLogin"
						label="Accept email and password sign-in"
						valuePropName="checked"
						tooltip="Turn off for a bucket whose users must come from an identity provider. Refused unless this bucket has an enabled provider."
					>
						<Switch />
					</Form.Item>
					{/*
					 * Disabled rather than hidden when password sign-in is off: the setting still exists and
					 * still means something, and hiding it would leave an operator wondering where it went.
					 * The server accepts it either way and returns the same explanation.
					 */}
					<Form.Item
						name="totpRequired"
						label="Require an authenticator app"
						valuePropName="checked"
						tooltip="Password sign-ins to this bucket must also carry a 6-digit code. Anyone without an authenticator sets one up at their next sign-in. Federated sign-in is not affected — the identity provider owns that policy."
					>
						<Switch disabled={bucket?.passwordLogin === false} />
					</Form.Item>
					<Form.Item
						name="registrationOpen"
						label="Self-service registration open"
						valuePropName="checked"
						tooltip="Allow visitors to register accounts in this bucket"
					>
						<Switch />
					</Form.Item>
					<Form.Item
						name="emailVerificationRequired"
						label="Require email verification"
						valuePropName="checked"
						tooltip="New accounts must confirm their email before they can sign in"
					>
						<Switch />
					</Form.Item>
					<Form.Item
						name="verificationMethod"
						label="Verification method"
						tooltip="How new registrants confirm their email"
					>
						<Select
							options={[
								{ label: 'Email link', value: 'link' },
								{ label: '6-digit code', value: 'code' }
							]}
						/>
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
