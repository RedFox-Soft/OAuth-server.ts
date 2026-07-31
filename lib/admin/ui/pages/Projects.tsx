import { useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	Space,
	Tag,
	Typography,
	message
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { Project } from '../../../adapters/types.js';
import { Clients } from './Clients.js';
import { BucketDetail } from './BucketDetail.js';

interface CreateProjectValues {
	name: string;
	slug: string;
}

/*
 * The origins editor. Validation is deliberately left to the server: it owns the one rule shared with
 * the request path, and its rejection names both the offending value and the canonical form it should
 * have been — a message worth showing verbatim rather than pre-empting with a weaker client-side regex.
 */
function OriginsEditor({
	project,
	onClose,
	onSaved
}: {
	project: Project;
	onClose: () => void;
	onSaved: () => void;
}) {
	const [origins, setOrigins] = useState<string[]>(project.corsOrigins ?? []);
	const [draft, setDraft] = useState('');
	const [saving, setSaving] = useState(false);

	function add() {
		const value = draft.trim();
		if (!value || origins.includes(value)) {
			setDraft('');
			return;
		}
		setOrigins([...origins, value]);
		setDraft('');
	}

	async function save() {
		setSaving(true);
		try {
			const res = await fetch(`/admin/api/projects/${project._id}`, {
				method: 'PATCH',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ corsOrigins: origins })
			});
			if (!res.ok) {
				const body = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				message.error(body?.message || 'failed to save origins');
				return;
			}
			onSaved();
			onClose();
		} finally {
			setSaving(false);
		}
	}

	return (
		<Modal
			title={`Browser origins — ${project.name}`}
			open
			onCancel={onClose}
			onOk={save}
			confirmLoading={saving}
			okText="Save"
			destroyOnHidden
		>
			<Typography.Paragraph type="secondary">
				Web origins allowed to call this project&apos;s clients from a browser.
				Exact match, no wildcards — e.g. <code>https://app.example.com</code>.
				An empty list allows none.
			</Typography.Paragraph>
			<Space
				wrap
				style={{ marginBottom: 12 }}
			>
				{origins.length === 0 && (
					<Typography.Text type="secondary">No origins</Typography.Text>
				)}
				{origins.map((origin) => (
					<Tag
						key={origin}
						closable
						onClose={() => setOrigins(origins.filter((o) => o !== origin))}
					>
						{origin}
					</Tag>
				))}
			</Space>
			<Space.Compact style={{ width: '100%' }}>
				<Input
					value={draft}
					placeholder="https://app.example.com"
					onChange={(e) => setDraft(e.target.value)}
					onPressEnter={add}
				/>
				<Button onClick={add}>Add</Button>
			</Space.Compact>
		</Modal>
	);
}

export function Projects({ isSuperAdmin }: { isSuperAdmin: boolean }) {
	const [projects, setProjects] = useState<Project[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [form] = Form.useForm<CreateProjectValues>();
	const [openProject, setOpenProject] = useState<Project | null>(null);
	const [openBucketId, setOpenBucketId] = useState<string | null>(null);
	const [originsFor, setOriginsFor] = useState<Project | null>(null);

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

	if (openBucketId) {
		return (
			<BucketDetail
				bucketId={openBucketId}
				onBack={() => setOpenBucketId(null)}
				isSuperAdmin={isSuperAdmin}
			/>
		);
	}

	if (openProject) {
		return (
			<Clients
				project={openProject}
				onBack={() => setOpenProject(null)}
			/>
		);
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
					},
					{
						title: 'Browser origins',
						dataIndex: 'corsOrigins',
						render: (corsOrigins: string[] | undefined) =>
							corsOrigins?.length ? corsOrigins.length : '—'
					},
					{
						title: '',
						render: (_: unknown, row: Project) => (
							<Space>
								<Button
									size="small"
									onClick={() => setOpenProject(row)}
								>
									Clients
								</Button>
								<Button
									size="small"
									disabled={!row.bucketId}
									onClick={() => row.bucketId && setOpenBucketId(row.bucketId)}
								>
									Users
								</Button>
								<Button
									size="small"
									onClick={() => setOriginsFor(row)}
								>
									Origins
								</Button>
							</Space>
						)
					}
				]}
			/>
			{originsFor && (
				<OriginsEditor
					project={originsFor}
					onClose={() => setOriginsFor(null)}
					onSaved={load}
				/>
			)}
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
