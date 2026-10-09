import { useCallback, useEffect, useState } from 'react';
import {
	Table,
	Button,
	Card,
	Modal,
	Form,
	Input,
	Popconfirm,
	Space,
	Switch,
	Tag,
	Typography,
	message
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { User } from '../../../adapters/types.js';

/* What the list answers: the account without its password, and whether it holds the instance privilege. */
type AdminUser = Pick<User, '_id' | 'email' | 'active'> & {
	superAdmin: boolean;
};

interface CreateAdminValues {
	email: string;
	password: string;
}

export function Admins() {
	const [admins, setAdmins] = useState<AdminUser[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [totpRequired, setTotpRequired] = useState(false);
	const [savingTotp, setSavingTotp] = useState(false);
	const [form] = Form.useForm<CreateAdminValues>();

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchAdmins = useCallback(async () => {
		try {
			const [list, settings] = await Promise.all([
				fetch('/admin/api/admins'),
				fetch('/admin/api/admins/settings')
			]);
			if (list.ok) setAdmins((await list.json()) as AdminUser[]);
			if (settings.ok) {
				const body = (await settings.json()) as { totpRequired: boolean };
				setTotpRequired(body.totpRequired);
			}
		} finally {
			setLoading(false);
		}
	}, []);
	function load() {
		setLoading(true);
		return fetchAdmins();
	}

	async function onToggleTotp(next: boolean) {
		setSavingTotp(true);
		try {
			const res = await fetch('/admin/api/admins/settings', {
				method: 'PATCH',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ totpRequired: next })
			});
			if (!res.ok) {
				const body = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				message.error(body?.message || 'failed to save the sign-in policy');
				return;
			}
			setTotpRequired(next);
			message.success(
				next
					? 'Administrators will be asked for an authenticator code from their next sign-in'
					: 'Administrators will sign in with a password alone'
			);
		} finally {
			setSavingTotp(false);
		}
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
			 * The reserved admin bucket's own sign-in policy. It lives here rather than on a bucket
			 * page because the admin bucket is deliberately absent from the bucket list — every other
			 * route refuses it, pointing at this namespace instead.
			 */}
			<Card
				size="small"
				style={{ marginBottom: 16 }}
			>
				<Space
					align="start"
					style={{ justifyContent: 'space-between', width: '100%' }}
				>
					<Space
						orientation="vertical"
						size={2}
					>
						<Typography.Text strong>
							Require an authenticator app
						</Typography.Text>
						{/*
						 * Both consequences an operator cannot see from here: nobody is locked out, and
						 * the console's own client is how an agent gets a token too.
						 */}
						<Typography.Text
							type="secondary"
							style={{ fontSize: 12 }}
						>
							Signing in to this console needs a 6-digit code as well as a
							password. Administrators without an authenticator set one up at
							their next sign-in, so nobody is locked out — including agents
							signing in through the console&rsquo;s own client.
						</Typography.Text>
					</Space>
					<Switch
						checked={totpRequired}
						loading={savingTotp}
						onChange={onToggleTotp}
					/>
				</Space>
			</Card>
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
					}
				]}
			/>
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
