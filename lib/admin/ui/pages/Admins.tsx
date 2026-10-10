import { useCallback, useEffect, useState } from 'react';
import {
	Table,
	Alert,
	Button,
	Modal,
	Form,
	Input,
	Popconfirm,
	Switch,
	Tag,
	message
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { User } from '../../../adapters/types.js';

/* What the list answers: the account without its password, and whether it holds the instance privilege. */
type AdminUser = Pick<User, '_id' | 'email' | 'active' | 'verified'> & {
	superAdmin: boolean;
};

interface CreateAdminValues {
	email: string;
	password: string;
}

export function Admins({
	onOpenSignInPolicy
}: {
	onOpenSignInPolicy?: () => void;
} = {}) {
	const [admins, setAdmins] = useState<AdminUser[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [form] = Form.useForm<CreateAdminValues>();
	const [editingEmail, setEditingEmail] = useState<AdminUser | null>(null);
	const [savingEmail, setSavingEmail] = useState(false);
	const [emailForm] = Form.useForm<{ email: string }>();

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchAdmins = useCallback(async () => {
		try {
			const list = await fetch('/admin/api/admins');
			if (list.ok) setAdmins((await list.json()) as AdminUser[]);
		} finally {
			setLoading(false);
		}
	}, []);
	function load() {
		setLoading(true);
		return fetchAdmins();
	}

	useEffect(() => {
		void fetchAdmins();
	}, [fetchAdmins]);

	/*
	 * The instance privilege is granted and withdrawn by operations of its own, never by an account edit, and
	 * the server refuses withdrawing it from the last active super administrator — its reason is shown as is.
	 */
	async function onSetSuperAdmin(target: AdminUser, next: boolean) {
		const res = await fetch(
			`/admin/api/admins/${encodeURIComponent(target._id)}/super-admin`,
			{ method: next ? 'POST' : 'DELETE' }
		);
		if (!res.ok) {
			const body = (await res.json().catch(() => null)) as {
				message?: string;
			} | null;
			message.error(body?.message || 'failed to change super administrator');
			return;
		}
		await load();
	}

	/*
	 * Corrects an administrator's address. The server leaves the account unverified at the new one and
	 * refuses changing your own while administrators must verify theirs; either refusal is shown as is.
	 */
	async function onChangeEmail(target: AdminUser, email: string) {
		setSavingEmail(true);
		try {
			const res = await fetch(
				`/admin/api/admins/${encodeURIComponent(target._id)}`,
				{
					method: 'PATCH',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ email })
				}
			);
			if (!res.ok) {
				const body = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				message.error(body?.message || 'failed to change the address');
				return;
			}
			setEditingEmail(null);
			await load();
		} finally {
			setSavingEmail(false);
		}
	}

	async function onCreate(values: CreateAdminValues) {
		setCreating(true);
		try {
			const res = await fetch('/admin/api/admins', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(values)
			});
			if (!res.ok) {
				const body = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				message.error(body?.message || 'failed to create admin');
				return;
			}
			setOpen(false);
			form.resetFields();
			await load();
		} finally {
			setCreating(false);
		}
	}

	return (
		<>
			{/*
			 * How administrators sign in — registration, email verification, an authenticator — is the
			 * console's own bucket's settings, edited where every bucket's are. Pointed at from here because
			 * this is where an operator looks for anything about administrators.
			 */}
			<Alert
				type="info"
				showIcon
				style={{ marginBottom: 16 }}
				title="Sign-in policy for administrators"
				description="Whether people may register an administrator account, whether administrators must verify their email, and whether an authenticator app is required are set on the Administrators bucket."
				action={
					onOpenSignInPolicy && (
						<Button
							size="small"
							onClick={onOpenSignInPolicy}
						>
							Open buckets
						</Button>
					)
				}
			/>
			<div style={{ marginBottom: 16, textAlign: 'right' }}>
				<Button
					type="primary"
					icon={<PlusOutlined />}
					onClick={() => setOpen(true)}
				>
					New admin
				</Button>
			</div>
			<Table<AdminUser>
				rowKey="_id"
				loading={loading}
				dataSource={admins}
				columns={[
					{ title: 'Email', dataIndex: 'email' },
					{
						title: 'Email verified',
						dataIndex: 'verified',
						render: (verified: boolean) =>
							verified ? (
								<Tag color="green">verified</Tag>
							) : (
								<Tag>unverified</Tag>
							)
					},
					{
						title: 'Super administrator',
						dataIndex: 'superAdmin',
						render: (superAdmin: boolean, row: AdminUser) => (
							<Popconfirm
								title={
									superAdmin
										? 'Withdraw super-administrator status?'
										: 'Make this administrator a super administrator?'
								}
								description={
									superAdmin
										? 'They keep their groups but lose authority over the whole instance.'
										: 'They gain authority over every group, setting and key of this instance.'
								}
								okText={superAdmin ? 'Withdraw' : 'Grant'}
								onConfirm={() => onSetSuperAdmin(row, !superAdmin)}
							>
								<Switch checked={superAdmin} />
							</Popconfirm>
						)
					},
					{
						title: 'Active',
						dataIndex: 'active',
						render: (active: boolean) =>
							active ? <Tag color="green">active</Tag> : <Tag>inactive</Tag>
					},
					{
						title: '',
						render: (_: unknown, row: AdminUser) => (
							<Button
								size="small"
								onClick={() => {
									emailForm.setFieldsValue({ email: row.email });
									setEditingEmail(row);
								}}
							>
								Change email
							</Button>
						)
					}
				]}
			/>
			<Modal
				title="Change email"
				open={editingEmail !== null}
				onCancel={() => setEditingEmail(null)}
				onOk={() => emailForm.submit()}
				confirmLoading={savingEmail}
				destroyOnHidden
			>
				<Form<{ email: string }>
					form={emailForm}
					layout="vertical"
					onFinish={({ email }) => {
						if (editingEmail) void onChangeEmail(editingEmail, email);
					}}
				>
					<Form.Item
						name="email"
						label="Email"
						rules={[{ required: true, type: 'email' }]}
						extra="The administrator must verify the new address before signing in, if administrators are required to verify theirs."
					>
						<Input autoComplete="off" />
					</Form.Item>
				</Form>
			</Modal>
			<Modal
				title="New admin"
				open={open}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				confirmLoading={creating}
				destroyOnHidden
			>
				<Form<CreateAdminValues>
					form={form}
					layout="vertical"
					onFinish={onCreate}
				>
					{/*
					 * An address beside a password is a sign-in form as far as a browser is concerned, and it
					 * filled this one with the *administrator's own* saved credentials — one distracted OK away
					 * from creating an account with their own email and password. `new-password` is the part
					 * that does the work: it is the documented signal not to offer a stored pair.
					 */}
					<Form.Item
						name="email"
						label="Email"
						rules={[{ required: true, type: 'email' }]}
					>
						<Input autoComplete="off" />
					</Form.Item>
					<Form.Item
						name="password"
						label="Password"
						rules={[{ required: true, min: 12 }]}
					>
						<Input.Password
							autoComplete="new-password"
							placeholder="at least 12 characters"
						/>
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
