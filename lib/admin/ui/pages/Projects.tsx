import { useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	Select,
	Space,
	Tag,
	Typography,
	message
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { Project, UserBucket } from '../../../adapters/types.js';
import { Clients } from './Clients.js';
import { Resources } from './Resources.js';
import { BucketDetail } from './BucketDetail.js';
import { assignableBuckets } from '../projects/model.js';
import { ConfirmDestruction } from '../ConfirmDestruction.js';

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

/*
 * The bucket selector.
 *
 * "Not set" is a real choice rather than an empty state, and it is the only way back: the assignment
 * route takes a bucket id and has no value meaning none, so clearing is its own DELETE. A project with
 * no bucket signs its users in from the default one, which is what `resolveBucketForRequest` falls
 * through to — so choosing the default and choosing nothing are the same act, and "Not set" is how
 * this screen offers it.
 *
 * What the endpoint returns is deliberately not what is offered: see `assignableBuckets`.
 */
function BucketEditor({
	project,
	onClose,
	onSaved
}: {
	project: Project;
	onClose: () => void;
	onSaved: () => void;
}) {
	const [buckets, setBuckets] = useState<UserBucket[]>([]);
	const [selected, setSelected] = useState<string | null>(
		project.bucketId ?? null
	);
	const [saving, setSaving] = useState(false);

	useEffect(() => {
		async function load() {
			const res = await fetch('/admin/api/buckets');
			if (res.ok) setBuckets((await res.json()) as UserBucket[]);
		}
		load();
	}, []);

	async function save() {
		setSaving(true);
		try {
			const base = `/admin/api/projects/${project._id}/bucket`;
			const res = selected
				? await fetch(base, {
						method: 'PUT',
						headers: { 'content-type': 'application/json' },
						body: JSON.stringify({ bucketId: selected })
					})
				: await fetch(base, { method: 'DELETE' });
			if (!res.ok) {
				const body = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				message.error(body?.message || 'failed to save the bucket');
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
			title={`Bucket — ${project.name}`}
			open
			onCancel={onClose}
			onOk={save}
			confirmLoading={saving}
			okText="Save"
			destroyOnHidden
		>
			<Typography.Paragraph type="secondary">
				Which population of end-users this project&apos;s clients sign in. Leave
				it unset to use the default bucket.
			</Typography.Paragraph>
			<Select<string | null>
				style={{ width: '100%' }}
				value={selected}
				onChange={setSelected}
				options={[
					{ value: null, label: 'Not set — use the default bucket' },
					...assignableBuckets(buckets, project).map((bucket) => ({
						value: bucket._id,
						label: bucket.name
					}))
				]}
			/>
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
	const [bucketFor, setBucketFor] = useState<Project | null>(null);
	const [resourcesFor, setResourcesFor] = useState<Project | null>(null);
	const [deleting, setDeleting] = useState<Project | null>(null);
	const [heldClients, setHeldClients] = useState<string[]>([]);
	const [destroying, setDestroying] = useState(false);

	async function load() {
		setLoading(true);
		try {
			const res = await fetch('/admin/api/projects');
			if (res.ok) setProjects((await res.json()) as Project[]);
		} finally {
			setLoading(false);
		}
	}

	/*
	 * The clients are fetched rather than read off the project, because `clientIds` can hold an id
	 * whose client no longer exists — and an administrator must not be shown a ghost as something they
	 * are about to destroy. The server drops the same ids for the same reason, so what is displayed
	 * here and what is destroyed there are the same set.
	 */
	async function openDelete(project: Project) {
		const res = await fetch(
			`/admin/api/projects/${encodeURIComponent(project._id)}/clients`
		);
		const clients = res.ok
			? ((await res.json()) as { clientId: string }[])
			: [];
		setHeldClients(clients.map((c) => c.clientId));
		setDeleting(project);
	}

	async function onDelete(project: Project, withCascade: boolean) {
		setDestroying(true);
		try {
			const params = new URLSearchParams();
			if (withCascade) {
				params.set('cascade', 'clients');
				// The set the administrator just reviewed, so a client that arrived while they were
				// reading is refused rather than destroyed on the strength of their consent.
				for (const clientId of heldClients) params.append('client', clientId);
			}
			const qs = params.toString();
			const res = await fetch(
				`/admin/api/projects/${encodeURIComponent(project._id)}${qs ? `?${qs}` : ''}`,
				{ method: 'DELETE' }
			);
			if (!res.ok) {
				// The server's own refusal names what is in the way and how many; "request failed" does not.
				const body = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				message.error(body?.message || `request failed (${res.status})`);
				return;
			}
			const body = (await res.json()) as {
				clientsDestroyed?: number;
				resourcesRemoved?: number;
			};
			message.success(
				`Project deleted — ${body.clientsDestroyed ?? 0} clients, ${body.resourcesRemoved ?? 0} resource declarations`
			);
			setDeleting(null);
			await load();
		} finally {
			setDestroying(false);
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

	if (resourcesFor) {
		return (
			<Resources
				project={resourcesFor}
				onBack={() => setResourcesFor(null)}
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
				locale={{
					emptyText:
						'No projects in this scope yet. Create one to register OAuth clients against — use the scope switcher above to work in a different group.'
				}}
				columns={[
					{ title: 'Name', dataIndex: 'name' },
					{ title: 'Slug', dataIndex: 'slug' },
					{
						title: 'Bucket',
						dataIndex: 'bucketId',
						render: (bucketId: string | null) => bucketId ?? 'default'
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
									onClick={() => setResourcesFor(row)}
								>
									Resources
								</Button>
								<Button
									size="small"
									onClick={() => setOriginsFor(row)}
								>
									Origins
								</Button>
								<Button
									size="small"
									onClick={() => setBucketFor(row)}
								>
									Bucket
								</Button>
								<Button
									size="small"
									danger
									onClick={() => openDelete(row)}
								>
									Delete
								</Button>
							</Space>
						)
					}
				]}
			/>
			{deleting && (
				<ConfirmDestruction
					open
					title={`Delete ${deleting.name}?`}
					consequences={[
						'The project is gone permanently. There is nothing left to inspect or restore.',
						'Every protected resource it declared stops being served.',
						/*
						 * Said on the screen rather than left to be discovered, because "delete the
						 * project" reads as if it might take the bucket with it, and an administrator
						 * who assumes that would delete a project to get rid of a population.
						 */
						deleting.bucketId
							? `Its user bucket (${deleting.bucketId}) is untouched — buckets are shared and outlive projects.`
							: 'No user bucket is affected.'
					]}
					cascade={
						heldClients.length > 0
							? {
									noun: 'clients',
									count: heldClients.length,
									onInspect: () => setOpenProject(deleting),
									inspectLabel: `Look at them first (${heldClients.join(', ')})`
								}
							: undefined
					}
					busy={destroying}
					onCancel={() => setDeleting(null)}
					onConfirm={(withCascade) => onDelete(deleting, withCascade)}
				/>
			)}
			{originsFor && (
				<OriginsEditor
					project={originsFor}
					onClose={() => setOriginsFor(null)}
					onSaved={load}
				/>
			)}
			{bucketFor && (
				<BucketEditor
					project={bucketFor}
					onClose={() => setBucketFor(null)}
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
