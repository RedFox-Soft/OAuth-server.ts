import { useEffect, useState } from 'react';
import {
	Table,
	Button,
	Card,
	Modal,
	Form,
	Input,
	Select,
	Space,
	Switch,
	Tag,
	Typography,
	message
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { User } from '../../../adapters/types.js';

type AdminUser = Omit<User, 'password'>;

interface CreateAdminValues {
	email: string;
	password: string;
	roles: string[];
}

const ROLE_OPTIONS = [
	{ label: 'Super admin', value: 'super_admin' },
	{ label: 'Project admin', value: 'project_admin' }
];

export function Admins() {
	const [admins, setAdmins] = useState<AdminUser[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [totpRequired, setTotpRequired] = useState(false);
	const [savingTotp, setSavingTotp] = useState(false);
	const [form] = Form.useForm<CreateAdminValues>();

	async function load() {
		setLoading(true);
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
		load();
	}, []);

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
						direction="vertical"
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
						title: 'Roles',
						dataIndex: 'roles',
						render: (roles: string[]) => (
							<>
								{roles.map((role) => (
									<Tag key={role}>{role}</Tag>
								))}
							</>
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
					initialValues={{ roles: ['project_admin'] }}
				>
					<Form.Item
						name="email"
						label="Email"
						rules={[{ required: true, type: 'email' }]}
					>
						<Input />
					</Form.Item>
					<Form.Item
						name="password"
						label="Password"
						rules={[{ required: true, min: 12 }]}
					>
						<Input.Password placeholder="at least 12 characters" />
					</Form.Item>
					<Form.Item
						name="roles"
						label="Roles"
						rules={[{ required: true }]}
					>
						<Select
							mode="multiple"
							options={ROLE_OPTIONS}
						/>
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
