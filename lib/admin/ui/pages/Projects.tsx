import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Table,
	Button,
	Modal,
	Form,
	Input,
	Space,
	Tag,
	Typography
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { Link, useNavigate } from '../frame/router.js';
import {
	bucketHref,
	projectHref,
	projectSettingsHref
} from '../frame/routes.js';
import { BucketField, GroupField } from '../frame/CreateDestination.js';
import { PageHeader } from '../frame/PageHeader.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { projectCan } from '../frame/can.js';
import { meCan, useMe } from '../frame/me.js';
import { Allowed } from '../frame/rights.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import type { ProjectView } from './ProjectWorkspace.js';

interface CreateProjectValues {
	name: string;
	slug: string;
	/* Chosen in the dialog (specs/087); the header's current group by default. */
	groupId?: string;
	bucketId?: string;
}

/*
 * The origins editor. Validation is deliberately left to the server: it owns the one rule shared with
 * the request path, and its rejection names both the offending value and the canonical form it should
 * have been — a message worth showing verbatim rather than pre-empting with a weaker client-side regex.
 * It stays on screen until the next edit, because it is the operator's guide to what to fix.
 */
function OriginsEditor({
	project,
	onClose,
	onSaved
}: {
	project: ProjectView;
	onClose: () => void;
	onSaved: () => void;
}) {
	const [origins, setOrigins] = useState<string[]>(project.corsOrigins);
	const [draft, setDraft] = useState('');
	const [saving, setSaving] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);
	const feedback = useFeedback();

	function edit(next: string[]) {
		setRefusal(null);
		setOrigins(next);
	}

	function add() {
		const value = draft.trim();
		if (!value || origins.includes(value)) {
			setDraft('');
			return;
		}
		edit([...origins, value]);
		setDraft('');
	}

	async function save() {
		setSaving(true);
		const result = await request(
			'PATCH',
			`/admin/api/projects/${project._id}`,
			{ corsOrigins: origins }
		);
		setSaving(false);
		if (!result.ok) {
			if (result.status >= 500) feedback.failed(result);
			else setRefusal(result.error.message);
			return;
		}
		feedback.done('Browser origins saved.');
		onSaved();
		onClose();
	}

	return (
		<Modal
			title={`Browser origins — ${project.name}`}
			open
			onCancel={onClose}
			onOk={() => void save()}
			confirmLoading={saving}
			okText="Save"
			destroyOnHidden
		>
			{refusal !== null && (
				<Alert
					type="error"
					showIcon
					style={{ marginBottom: 12 }}
					title={refusal}
				/>
			)}
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
						onClose={() => edit(origins.filter((o) => o !== origin))}
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

export function Projects() {
	const [projects, setProjects] = useState<ProjectView[]>([]);
	const [loading, setLoading] = useState(true);
	const [loadFailed, setLoadFailed] = useState<string | null>(null);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [form] = Form.useForm<CreateProjectValues>();
	const navigate = useNavigate();
	const feedback = useFeedback();
	const { me } = useMe();
	const [originsFor, setOriginsFor] = useState<ProjectView | null>(null);

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchProjects = useCallback(
		() =>
			request<ProjectView[]>('GET', '/admin/api/projects').then((result) => {
				if (result.ok) {
					setProjects(result.data);
					setLoadFailed(null);
				} else {
					setLoadFailed(result.error.message);
				}
				setLoading(false);
			}),
		[]
	);
	function load() {
		setLoading(true);
		return fetchProjects();
	}

	useEffect(() => {
		void fetchProjects();
	}, [fetchProjects]);

	async function onCreate(values: CreateProjectValues) {
		setCreating(true);
		const result = await request<{ _id: string }>(
			'POST',
			'/admin/api/projects',
			values
		);
		setCreating(false);
		if (!result.ok) {
			feedback.failed(result, form);
			return;
		}
		feedback.done(`Project ${values.name} created.`);
		setOpen(false);
		form.resetFields();
		// Opened at once: it may belong to a group other than the header's, where the list would not show it.
		void navigate(projectHref(result.data._id));
	}

	/*
	 * A project's bucket, group and deletion are changed on its Settings tab (specs/085), so the row offers
	 * the way there rather than a dialog over the list.
	 */
	function actionsFor(row: ProjectView): RowAction[] {
		const can = projectCan(row);
		const items: RowAction[] = [];
		if (can.edit) {
			items.push({
				key: 'origins',
				label: 'Edit origins…',
				group: 'edit',
				onClick: () => setOriginsFor(row)
			});
		}
		if (can.assignBucket) {
			items.push({
				key: 'bucket',
				label: 'Change bucket…',
				group: 'edit',
				onClick: () =>
					void navigate(projectSettingsHref(row._id, { card: 'bucket' }))
			});
		}
		if (can.move) {
			items.push({
				key: 'move',
				label: 'Move to group…',
				group: 'handover',
				onClick: () =>
					void navigate(projectSettingsHref(row._id, { card: 'ownership' }))
			});
		}
		if (can.delete) {
			items.push({
				key: 'delete',
				label: 'Delete…',
				group: 'danger',
				onClick: () =>
					void navigate(projectSettingsHref(row._id, { card: 'danger' }))
			});
		}
		return items;
	}

	const mayCreate = meCan(me).createProject;
	const newProject = (
		<Button
			type="primary"
			icon={<PlusOutlined />}
			onClick={() => setOpen(true)}
		>
			New project
		</Button>
	);

	return (
		<>
			<PageHeader
				title="Projects"
				actions={<Allowed when={mayCreate}>{newProject}</Allowed>}
			/>
			{loadFailed !== null ? (
				<LoadFailed
					reason={loadFailed}
					onRetry={() => void load()}
				/>
			) : (
				<Table<ProjectView>
					rowKey="_id"
					loading={loading}
					dataSource={projects}
					locale={{
						emptyText: (
							<EmptyState
								purpose="No projects in this scope yet. Create one to register OAuth clients against — use the scope switcher above to work in a different group."
								create={mayCreate ? newProject : undefined}
							/>
						)
					}}
					columns={[
						{
							title: 'Name',
							dataIndex: 'name',
							render: (name: string, row: ProjectView) => (
								<Link href={projectHref(row._id)}>{name}</Link>
							)
						},
						{ title: 'Slug', dataIndex: 'slug' },
						{
							title: 'Bucket',
							key: 'bucket',
							render: (_: unknown, row: ProjectView) =>
								row.bucket ? (
									<Link href={bucketHref(row.bucket.id)}>
										{row.bucket.name}
									</Link>
								) : (
									<Typography.Text type="secondary">
										Default bucket
									</Typography.Text>
								)
						},
						{
							title: 'Applications',
							key: 'applications',
							render: (_: unknown, row: ProjectView) =>
								row.clientCount ?? row.clientIds.length
						},
						{
							title: 'Browser origins',
							dataIndex: 'corsOrigins',
							render: (corsOrigins: string[] | undefined) =>
								corsOrigins?.length ? corsOrigins.length : '—'
						},
						{
							title: '',
							key: 'actions',
							render: (_: unknown, row: ProjectView) => (
								<RowActions
									name={row.name}
									items={actionsFor(row)}
								/>
							)
						}
					]}
				/>
			)}
			{originsFor && (
				<OriginsEditor
					project={originsFor}
					onClose={() => setOriginsFor(null)}
					onSaved={() => void load()}
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
					scrollToFirstError
					onFinish={(values) => void onCreate(values)}
				>
					<GroupField />
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
					<BucketField />
				</Form>
			</Modal>
		</>
	);
}
