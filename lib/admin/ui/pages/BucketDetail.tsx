import { useEffect, useState } from 'react';
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
	Popconfirm,
	message
} from 'antd';
import { ArrowLeftOutlined, PlusOutlined } from '@ant-design/icons';
import type { UserBucket, User } from '../../../adapters/types.js';

type EndUser = Omit<User, 'password'>;

interface CreateValues {
	email: string;
	password: string;
	roles?: string[];
}

export function BucketDetail({
	bucketId,
	onBack,
	isSuperAdmin
}: {
	bucketId: string;
	onBack: () => void;
	isSuperAdmin: boolean;
}) {
	const base = `/admin/api/buckets/${encodeURIComponent(bucketId)}`;
	const [bucket, setBucket] = useState<UserBucket | null>(null);
	const [rows, setRows] = useState<EndUser[]>([]);
	const [loading, setLoading] = useState(true);
	const [createOpen, setCreateOpen] = useState(false);
	const [editOpen, setEditOpen] = useState(false);
	const [pwUser, setPwUser] = useState<EndUser | null>(null);
	const [bucketEditOpen, setBucketEditOpen] = useState(false);
	const [saving, setSaving] = useState(false);
	const [createForm] = Form.useForm<CreateValues>();
	const [editForm] = Form.useForm<{ roles?: string[]; active: boolean }>();
	const [pwForm] = Form.useForm<{ password: string }>();
	const [bucketForm] = Form.useForm<{ name: string; roles?: string[] }>();

	const roleOptions = (bucket?.roles ?? []).map((r) => ({ label: r, value: r }));

	async function load() {
		setLoading(true);
		try {
			const [b, u] = await Promise.all([fetch(base), fetch(`${base}/users`)]);
			if (b.ok) setBucket((await b.json()) as UserBucket);
			if (u.ok) setRows((await u.json()) as EndUser[]);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [bucketId]);

	async function post(path: string, bodyObj: unknown, okMsg: string) {
		const res = await fetch(`${base}${path}`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(bodyObj)
		});
		const body = (await res.json().catch(() => null)) as { message?: string } | null;
		if (!res.ok) {
			message.error(body?.message || `failed: ${okMsg}`);
			return false;
		}
		return true;
	}

	async function onCreate(values: CreateValues) {
		setSaving(true);
		try {
			if (await post('/users', values, 'create user')) {
				setCreateOpen(false);
				createForm.resetFields();
				await load();
			}
		} finally {
			setSaving(false);
		}
	}

	async function onEdit(values: { roles?: string[]; active: boolean }) {
		if (!editUserId) return;
		const res = await fetch(`${base}/users/${editUserId}`, {
			method: 'PATCH',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(values)
		});
		if (!res.ok) {
			message.error('failed to update user');
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

	async function onDelete(uid: string) {
		const res = await fetch(`${base}/users/${uid}`, { method: 'DELETE' });
		if (!res.ok) {
			message.error('failed to delete user');
			return;
		}
		await load();
	}

	async function onSaveBucket(values: { name: string; roles?: string[] }) {
		const res = await fetch(base, {
			method: 'PATCH',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(values)
		});
		if (!res.ok) {
			message.error('failed to update bucket');
			return;
		}
		setBucketEditOpen(false);
		await load();
	}

	return (
		<>
			<Space style={{ marginBottom: 16, justifyContent: 'space-between', width: '100%' }}>
				<Button icon={<ArrowLeftOutlined />} onClick={onBack}>
					Back
				</Button>
				<Typography.Title level={4} style={{ margin: 0 }}>
					{bucket?.name ?? bucketId} — users
				</Typography.Title>
				<Space>
					<Button
						onClick={() => {
							bucketForm.setFieldsValue({
								name: bucket?.name ?? '',
								roles: bucket?.roles ?? []
							});
							setBucketEditOpen(true);
						}}
					>
						Edit bucket
					</Button>
					<Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
						New user
					</Button>
				</Space>
			</Space>
			<div style={{ marginBottom: 12 }}>
				{(bucket?.roles ?? []).map((r) => (
					<Tag key={r}>{r}</Tag>
				))}
			</div>
			<Table<EndUser>
				rowKey="_id"
				loading={loading}
				dataSource={rows}
				columns={[
					{ title: 'Email', dataIndex: 'email' },
					{
						title: 'Roles',
						dataIndex: 'roles',
						render: (roles: string[]) => roles.map((r) => <Tag key={r}>{r}</Tag>)
					},
					{
						title: 'Active',
						dataIndex: 'active',
						render: (a: boolean) => (a ? <Tag color="green">active</Tag> : <Tag>inactive</Tag>)
					},
					{
						title: 'Verified',
						dataIndex: 'verified',
						render: (v: boolean) => (v ? 'yes' : 'no')
					},
					{
						title: 'Actions',
						render: (_: unknown, row: EndUser) => (
							<Space>
								<Button
									size="small"
									onClick={() => {
										setEditUserId(row._id);
										editForm.setFieldsValue({ roles: row.roles, active: row.active });
										setEditOpen(true);
									}}
								>
									Edit
								</Button>
								<Button size="small" onClick={() => setPwUser(row)}>
									Reset password
								</Button>
								<Popconfirm title="Delete this user?" onConfirm={() => onDelete(row._id)}>
									<Button size="small" danger>
										Delete
									</Button>
								</Popconfirm>
							</Space>
						)
					}
				]}
			/>

			<Modal
				title="New user"
				open={createOpen}
				onCancel={() => setCreateOpen(false)}
				onOk={() => createForm.submit()}
				confirmLoading={saving}
				destroyOnHidden
			>
				<Form<CreateValues> form={createForm} layout="vertical" onFinish={onCreate}>
					<Form.Item name="email" label="Email" rules={[{ required: true, type: 'email' }]}>
						<Input />
					</Form.Item>
					<Form.Item name="password" label="Initial password" rules={[{ required: true, min: 8 }]}>
						<Input.Password placeholder="at least 8 characters" />
					</Form.Item>
					<Form.Item name="roles" label="Roles">
						<Select mode="multiple" options={roleOptions} />
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
				<Form form={editForm} layout="vertical" onFinish={onEdit}>
					<Form.Item name="roles" label="Roles">
						<Select mode="multiple" options={roleOptions} />
					</Form.Item>
					<Form.Item name="active" label="Active" valuePropName="checked">
						<Switch />
					</Form.Item>
				</Form>
			</Modal>

			<Modal
				title="Reset password"
				open={pwUser !== null}
				onCancel={() => setPwUser(null)}
				onOk={() => pwForm.submit()}
				destroyOnHidden
			>
				<Form form={pwForm} layout="vertical" onFinish={onResetPassword}>
					<Form.Item name="password" label="New password" rules={[{ required: true, min: 8 }]}>
						<Input.Password />
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
				<Form form={bucketForm} layout="vertical" onFinish={onSaveBucket}>
					<Form.Item name="name" label="Name" rules={[{ required: true }]}>
						<Input />
					</Form.Item>
					<Form.Item name="roles" label="Roles" tooltip="Role set users in this bucket may hold">
						<Select mode="tags" placeholder="add role names" />
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
