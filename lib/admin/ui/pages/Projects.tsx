import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Table,
	Button,
	Modal,
	Form,
	Input,
	Select,
	Space,
	Tag,
	Typography
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { UserBucket } from '../../../adapters/types.js';
import { Link, useNavigate } from '../frame/router.js';
import { bucketHref, projectHref } from '../frame/routes.js';
import { DEFAULT_BUCKET_ID } from '../../consts.js';
import { assignableBuckets } from '../projects/model.js';
import { ConfirmDestruction } from '../ConfirmDestruction.js';
import { MoveToGroup } from '../MoveToGroup.js';
import { PageHeader } from '../frame/PageHeader.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { ACTIONS } from '../frame/actions.js';
import { projectCan } from '../frame/can.js';
import { meCan, useMe } from '../frame/me.js';
import { Allowed } from '../frame/rights.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import type { ProjectView } from './ProjectWorkspace.js';

interface CreateProjectValues {
	name: string;
	slug: string;
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

/*
 * The bucket selector.
 *
 * "Not set" is a real choice rather than an empty state, and it is the only way back: the assignment
 * route takes a bucket id and has no value meaning none, so clearing is its own DELETE. A project with
 * no bucket signs its users in from the default one, which is what `resolveBucketForRequest` falls
 * through to — so choosing the default and choosing nothing are the same act, and "Not set" is how
 * this screen offers it.
 *
 * It only chooses: the change itself is confirmed (C2) and sent by the list once this dialog has
 * closed, so the confirmation never opens on top of it.
 *
 * What the endpoint returns is deliberately not what is offered: see `assignableBuckets`.
 */
function BucketEditor({
	project,
	onClose,
	onChoose
}: {
	project: ProjectView;
	onClose: () => void;
	onChoose: (bucketId: string | null, bucketName: string) => void;
}) {
	const [buckets, setBuckets] = useState<UserBucket[] | null>(null);
	const [loadError, setLoadError] = useState<string | null>(null);
	const [selected, setSelected] = useState<string | null>(
		project.bucketId ?? null
	);

	useEffect(() => {
		void (async () => {
			const result = await request<UserBucket[]>('GET', '/admin/api/buckets');
			if (result.ok) setBuckets(result.data);
			else setLoadError(result.error.message);
		})();
	}, []);

	function choose() {
		if (selected === (project.bucketId ?? null)) {
			onClose();
			return;
		}
		const name =
			selected === null
				? 'the default bucket'
				: (buckets?.find((b) => b._id === selected)?.name ?? selected);
		onChoose(selected, name);
	}

	return (
		<Modal
			title={`Change bucket — ${project.name}`}
			open
			onCancel={onClose}
			onOk={choose}
			okText="Change bucket"
			okButtonProps={{ disabled: buckets === null }}
			destroyOnHidden
		>
			<Typography.Paragraph type="secondary">
				Which population of end-users this project&apos;s clients sign in. Leave
				it unset to use the default bucket.
			</Typography.Paragraph>
			{loadError !== null ? (
				<Alert
					type="error"
					showIcon
					title={loadError}
				/>
			) : (
				<Select<string | null>
					style={{ width: '100%' }}
					loading={buckets === null}
					value={selected}
					onChange={setSelected}
					options={[
						{ value: null, label: 'Not set — use the default bucket' },
						...assignableBuckets(buckets ?? [], project).map((bucket) => ({
							value: bucket._id,
							label: bucket.name
						}))
					]}
				/>
			)}
		</Modal>
	);
}

export function Projects() {
	const [projects, setProjects] = useState<ProjectView[]>([]);
	// The buckets this administrator can see, by id: a project's bucket is shown by name and opens it.
	const [bucketNames, setBucketNames] = useState<Map<string, string>>(
		new Map()
	);
	const [loading, setLoading] = useState(true);
	const [loadFailed, setLoadFailed] = useState<string | null>(null);
	const [open, setOpen] = useState(false);
	const [creating, setCreating] = useState(false);
	const [form] = Form.useForm<CreateProjectValues>();
	const navigate = useNavigate();
	const feedback = useFeedback();
	const confirm = useConfirm();
	const { me } = useMe();
	const [originsFor, setOriginsFor] = useState<ProjectView | null>(null);
	const [bucketFor, setBucketFor] = useState<ProjectView | null>(null);
	const [deleting, setDeleting] = useState<ProjectView | null>(null);
	const [heldClients, setHeldClients] = useState<string[]>([]);
	const [destroying, setDestroying] = useState(false);
	const [moving, setMoving] = useState<ProjectView | null>(null);

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchProjects = useCallback(
		() =>
			Promise.all([
				request<ProjectView[]>('GET', '/admin/api/projects'),
				request<UserBucket[]>('GET', '/admin/api/buckets')
			]).then(([result, bucketsResult]) => {
				if (result.ok) {
					setProjects(result.data);
					setLoadFailed(null);
				} else {
					setLoadFailed(result.error.message);
				}
				if (bucketsResult.ok) {
					setBucketNames(
						new Map(bucketsResult.data.map((b) => [b._id, b.name]))
					);
				}
				setLoading(false);
			}),
		[]
	);
	function load() {
		setLoading(true);
		return fetchProjects();
	}

	/*
	 * The clients are fetched rather than read off the project, because `clientIds` can hold an id
	 * whose client no longer exists — and an administrator must not be shown a ghost as something they
	 * are about to destroy. The server drops the same ids for the same reason, so what is displayed
	 * here and what is destroyed there are the same set.
	 */
	async function openDelete(project: ProjectView) {
		const result = await request<{ clientId: string }[]>(
			'GET',
			`/admin/api/projects/${encodeURIComponent(project._id)}/clients`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		setHeldClients(result.data.map((c) => c.clientId));
		setDeleting(project);
	}

	async function onDelete(project: ProjectView, withCascade: boolean) {
		setDestroying(true);
		const params = new URLSearchParams();
		if (withCascade) {
			params.set('cascade', 'clients');
			// The set the administrator just reviewed, so a client that arrived while they were
			// reading is refused rather than destroyed on the strength of their consent.
			for (const clientId of heldClients) params.append('client', clientId);
		}
		const qs = params.toString();
		const result = await request<{
			clientsDestroyed?: number;
			resourcesRemoved?: number;
		}>(
			'DELETE',
			`/admin/api/projects/${encodeURIComponent(project._id)}${qs ? `?${qs}` : ''}`
		);
		setDestroying(false);
		if (!result.ok) {
			// The server's own refusal names what is in the way and how many.
			feedback.failed(result);
			return;
		}
		const clients = result.data.clientsDestroyed ?? 0;
		const resources = result.data.resourcesRemoved ?? 0;
		feedback.done(
			`Project deleted, with ${String(clients)} client${clients === 1 ? '' : 's'} and ${String(resources)} resource declaration${resources === 1 ? '' : 's'}.`
		);
		setDeleting(null);
		await load();
	}

	async function changeBucket(
		project: ProjectView,
		bucketId: string | null,
		bucketName: string
	) {
		setBucketFor(null);
		const from = project.bucketId
			? (bucketNames.get(project.bucketId) ?? project.bucketId)
			: 'the default bucket';
		const agreed = await confirm('project.bucket.change', {
			target: project.name,
			consequences: [
				`Its clients sign people in from ${bucketName} instead of ${from}.`,
				'Where the two buckets are different issuers, its tokens carry the new issuer, and an integration that checks it must be updated.',
				'No account moves: people sign in with an account of the new bucket.'
			]
		});
		if (!agreed) return;
		const base = `/admin/api/projects/${project._id}/bucket`;
		const result = bucketId
			? await request('PUT', base, { bucketId })
			: await request('DELETE', base);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done('Project bucket changed.');
		await load();
	}

	useEffect(() => {
		void fetchProjects();
	}, [fetchProjects]);

	async function onCreate(values: CreateProjectValues) {
		setCreating(true);
		const result = await request('POST', '/admin/api/projects', values);
		setCreating(false);
		if (!result.ok) {
			feedback.failed(result, form);
			return;
		}
		feedback.done('Project created.');
		setOpen(false);
		form.resetFields();
		await load();
	}

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
				onClick: () => setBucketFor(row)
			});
		}
		if (can.move) {
			items.push({
				key: 'move',
				label: 'Move to group…',
				group: 'handover',
				onClick: () => setMoving(row),
				// A project and its bucket share a group, so the bucket is what moves.
				blocked:
					(row.blockers?.hasBucket ?? Boolean(row.bucketId))
						? 'Moves with its bucket — move the bucket instead'
						: null
			});
		}
		if (can.delete) {
			items.push({
				key: 'delete',
				label: 'Delete…',
				group: 'danger',
				onClick: () => void openDelete(row)
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
							dataIndex: 'bucketId',
							render: (bucketId: string | null) => {
								const id = bucketId ?? DEFAULT_BUCKET_ID;
								const name = bucketNames.get(id);
								// A bucket in a group this administrator is not in is named by id, not linked.
								if (name === undefined) return bucketId ?? 'Default';
								return <Link href={bucketHref(id)}>{name}</Link>;
							}
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
			{moving && (
				<MoveToGroup
					kind="project"
					id={moving._id}
					name={moving.name}
					sourceGroupId={moving.ownerGroupId}
					onClose={() => setMoving(null)}
					onMoved={() => {
						setMoving(null);
						void load();
					}}
				/>
			)}
			{deleting && (
				<ConfirmDestruction
					open
					title={`Delete ${deleting.name}?`}
					word={ACTIONS['project.delete'].word}
					consequences={[
						'The project is gone permanently. There is nothing left to inspect or restore.',
						'Every protected resource it declared stops being served.',
						/*
						 * Said on the screen rather than left to be discovered, because "delete the
						 * project" reads as if it might take the bucket with it, and an administrator
						 * who assumes that would delete a project to get rid of a population.
						 */
						deleting.bucketId
							? `Its user bucket (${bucketNames.get(deleting.bucketId) ?? deleting.bucketId}) is untouched — buckets are shared and outlive projects.`
							: 'No user bucket is affected.'
					]}
					cascade={
						heldClients.length > 0
							? {
									noun: 'clients',
									count: heldClients.length,
									onInspect: () => {
										setDeleting(null);
										void navigate(projectHref(deleting._id, 'clients'));
									},
									inspectLabel: `Look at them first (${heldClients.join(', ')})`
								}
							: undefined
					}
					busy={destroying}
					onCancel={() => setDeleting(null)}
					onConfirm={(withCascade) => void onDelete(deleting, withCascade)}
				/>
			)}
			{originsFor && (
				<OriginsEditor
					project={originsFor}
					onClose={() => setOriginsFor(null)}
					onSaved={() => void load()}
				/>
			)}
			{bucketFor && (
				<BucketEditor
					project={bucketFor}
					onClose={() => setBucketFor(null)}
					onChoose={(bucketId, bucketName) =>
						void changeBucket(bucketFor, bucketId, bucketName)
					}
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
