import { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Tag, message } from 'antd';
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
	const [form] = Form.useForm<CreateAdminValues>();

	async function load() {
		setLoading(true);
		try {
			const res = await fetch('/admin/api/admins');
			if (res.ok) setAdmins((await res.json()) as AdminUser[]);
		} finally {
			setLoading(false);
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
