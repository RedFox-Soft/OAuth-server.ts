import { useEffect, useState } from 'react';
import { Table, Button, Modal, Form, Input, message } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { Project } from '../../../adapters/types.js';

interface CreateProjectValues {
	name: string;
	slug: string;
}

export function Projects() {
	const [projects, setProjects] = useState<Project[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [form] = Form.useForm<CreateProjectValues>();

	async function load() {
		setLoading(true);
		try {
			const res = await fetch('/admin/api/projects');
			if (res.ok) setProjects((await res.json()) as Project[]);
		} finally {
			setLoading(false);
		}
	}

	useEffect(() => {
		load();
	}, []);

	async function onCreate(values: CreateProjectValues) {
		setCreating(true);
		try {
			const res = await fetch('/admin/api/projects', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(values)
			});
			if (!res.ok) {
				const body = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				message.error(body?.message || 'failed to create project');
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
					New project
				</Button>
			</div>
			<Table<Project>
				rowKey="_id"
				loading={loading}
				dataSource={projects}
				columns={[
					{ title: 'Name', dataIndex: 'name' },
					{ title: 'Slug', dataIndex: 'slug' },
					{ title: 'Bucket', dataIndex: 'bucketId' },
					{
						title: 'Managed by',
						dataIndex: 'managedBy',
						render: (managedBy: string[]) => managedBy.join(', ')
					}
				]}
			/>
			<Modal
				title="New project"
				open={open}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				confirmLoading={creating}
				destroyOnHidden
			>
				<Form<CreateProjectValues>
					form={form}
					layout="vertical"
					onFinish={onCreate}
				>
					<Form.Item
						name="name"
						label="Name"
						rules={[{ required: true }]}
					>
						<Input />
					</Form.Item>
					<Form.Item
						name="slug"
						label="Slug"
						rules={[{ required: true, pattern: /^[a-z0-9-]+$/ }]}
					>
						<Input placeholder="lowercase, digits, hyphens" />
					</Form.Item>
				</Form>
			</Modal>
		</>
	);
}
