import { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, Select, Tag, message } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { UserBucket, Project } from '../../../adapters/types.js';
import { BucketDetail } from './BucketDetail.js';

interface CreateBucketValues {
	name: string;
	roles?: string[];
}

export function Buckets({ isSuperAdmin }: { isSuperAdmin: boolean }) {
	const [buckets, setBuckets] = useState<UserBucket[]>([]);
	const [projects, setProjects] = useState<Project[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [form] = Form.useForm<CreateBucketValues>();
	const [openBucketId, setOpenBucketId] = useState<string | null>(null);

	async function load() {
		setLoading(true);
		try {
			const [b, p] = await Promise.all([
				fetch('/admin/api/buckets'),
				fetch('/admin/api/projects')
			]);
			if (b.ok) setBuckets((await b.json()) as UserBucket[]);
			if (p.ok) setProjects((await p.json()) as Project[]);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
	}, []);

	async function onCreate(values: CreateBucketValues) {
		setCreating(true);
		try {
			const res = await fetch('/admin/api/buckets', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(values)
			});
			if (!res.ok) {
				const body = (await res.json().catch(() => null)) as { message?: string } | null;
				message.error(body?.message || 'failed to create bucket');
				return;
			}
			setOpen(false);
			form.resetFields();
			await load();
		} finally {
			setCreating(false);
		}
	}

	function projectCount(bucketId: string): number {
		return projects.filter((p) => p.bucketId === bucketId).length;
	}

	if (openBucketId) {
		return (
			<BucketDetail
				bucketId={openBucketId}
				onBack={() => {
					setOpenBucketId(null);
					load();
				}}
				isSuperAdmin={isSuperAdmin}
			/>
		);
	}

	return (
		<>
			{isSuperAdmin && (
				<div style={{ marginBottom: 16, textAlign: 'right' }}>
					<Button type="primary" icon={<PlusOutlined />} onClick={() => setOpen(true)}>
						New bucket
					</Button>
				</div>
			)}
			<Table<UserBucket>
				rowKey="_id"
				loading={loading}
				dataSource={buckets}
				columns={[
					{ title: 'Name', dataIndex: 'name' },
					{
						title: 'Roles',
						dataIndex: 'roles',
						render: (roles: string[]) => roles.map((r) => <Tag key={r}>{r}</Tag>)
					},
					{
						title: 'Projects',
						render: (_: unknown, row: UserBucket) => projectCount(row._id)
					},
					{
						title: '',
						render: (_: unknown, row: UserBucket) => (
							<Button size="small" onClick={() => setOpenBucketId(row._id)}>
								Users
							</Button>
						)
					}
				]}
			/>
			<Modal
				title="New bucket"
				open={open}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				confirmLoading={creating}
				destroyOnHidden
			>
				<Form<CreateBucketValues> form={form} layout="vertical" onFinish={onCreate}>
					<Form.Item name="name" label="Name" rules={[{ required: true }]}>
						<Input />
					</Form.Item>
					<Form.Item name="roles" label="Roles">
						<Select mode="tags" placeholder="add role names" />
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
