import { useEffect, useRef, useState } from 'react';
import { Button, Card, Flex, Form, Input, Space, Typography } from 'antd';
import { ConfirmDestruction } from '../../ConfirmDestruction.js';
import { MoveToGroup } from '../../MoveToGroup.js';
import { ACTIONS } from '../../frame/actions.js';
import { projectCan } from '../../frame/can.js';
import { useFeedback } from '../../frame/feedback.js';
import { request } from '../../frame/request.js';
import {
	Link,
	useLeaveGuard,
	useNavigate,
	useRoute
} from '../../frame/router.js';
import { bucketHref, projectHref } from '../../frame/routes.js';
import { groupLabel } from '../../../groups/label.js';
import type { ScopeOption } from '../ScopeSwitcher.js';
import type { ProjectView } from '../ProjectWorkspace.js';
import { ChangeBucketDialog } from './ChangeBucketDialog.js';
import { DEFAULT_BUCKET_ID } from '../../../consts.js';

const FORM_LABEL: Record<string, string> = {
	root: "served at the server's root",
	path: 'a path of the server',
	host: 'a hostname of its own',
	unaddressed: 'no address of its own yet'
};

function plural(n: number, one: string, many: string): string {
	return `${String(n)} ${n === 1 ? one : many}`;
}

function GeneralCard({
	project,
	canEdit,
	onChanged
}: {
	project: ProjectView;
	canEdit: boolean;
	onChanged: () => void;
}) {
	const feedback = useFeedback();
	const [form] = Form.useForm<{ name: string }>();
	// Undefined until the form mounts, whatever the field's type says.
	const name = Form.useWatch('name', form) as string | undefined;
	const [saving, setSaving] = useState(false);
	const dirty = name !== undefined && name !== project.name;
	useLeaveGuard(dirty, dirty ? 1 : 0);

	async function save(values: { name: string }) {
		setSaving(true);
		const result = await request(
			'PATCH',
			`/admin/api/projects/${encodeURIComponent(project._id)}`,
			{ name: values.name }
		);
		setSaving(false);
		if (!result.ok) {
			feedback.failed(result, form);
			return;
		}
		feedback.done(`Project renamed to “${values.name}”.`);
		onChanged();
	}

	return (
		<Card title="General">
			<Form
				form={form}
				layout="vertical"
				initialValues={{ name: project.name }}
				onFinish={(values) => void save(values)}
				disabled={!canEdit}
				scrollToFirstError
			>
				<Form.Item
					name="name"
					label="Name"
					extra="Changing it does not affect applications."
					rules={[{ required: true, whitespace: true }]}
				>
					<Input style={{ maxWidth: 420 }} />
				</Form.Item>
				<Form.Item label="Slug">
					<Typography.Text code>{project.slug}</Typography.Text>
				</Form.Item>
				{canEdit && (
					<Space>
						<Button
							type="primary"
							htmlType="submit"
							loading={saving}
							disabled={!dirty}
						>
							Save
						</Button>
						<Button
							disabled={!dirty}
							onClick={() => form.setFieldsValue({ name: project.name })}
						>
							Reset
						</Button>
					</Space>
				)}
			</Form>
		</Card>
	);
}

/*
 * The bucket the project signs people into (specs/085). The change is made only here, on the project that
 * owns the field; a bucket's Overview offers "Use in a project…", which leads back to this card.
 */
function BucketCard({
	project,
	canAssign,
	preselect,
	onChanged
}: {
	project: ProjectView;
	canAssign: boolean;
	preselect: string | undefined;
	onChanged: () => void;
}) {
	const [dialog, setDialog] = useState(Boolean(preselect && canAssign));
	const bucket = project.bucket ?? null;
	const onDefault = project.bucketId === DEFAULT_BUCKET_ID;
	const apps = project.clientCount ?? project.clientIds.length;

	return (
		<Card
			id="bucket"
			title="Bucket"
		>
			<Flex
				vertical
				gap={12}
			>
				{onDefault ? (
					<Typography.Text>
						This project uses the shared Default bucket, whose people only
						instance administrators manage. Choose a bucket of its group to keep
						this project&apos;s people apart, or{' '}
						<Link href="/admin/buckets">create a new bucket</Link> first.
					</Typography.Text>
				) : bucket ? (
					<Typography.Text>
						Signs people in from{' '}
						<Link href={bucketHref(bucket.id)}>{bucket.name}</Link>,{' '}
						{FORM_LABEL[bucket.addressForm] ?? bucket.addressForm}.{' '}
						{plural(apps, 'application uses', 'applications use')} its issuer.
					</Typography.Text>
				) : (
					<Typography.Text>
						Signs people in from bucket {project.bucketId}, which no longer
						exists.
					</Typography.Text>
				)}
				{canAssign ? (
					<Space wrap>
						<Button onClick={() => setDialog(true)}>Change bucket…</Button>
					</Space>
				) : (
					<Typography.Text type="secondary">
						Only an owner of the project&apos;s group can change its bucket.
					</Typography.Text>
				)}
			</Flex>
			{dialog && (
				<ChangeBucketDialog
					project={project}
					preselect={preselect}
					onClose={() => setDialog(false)}
					onChanged={() => {
						setDialog(false);
						onChanged();
					}}
				/>
			)}
		</Card>
	);
}

export function ProjectSettings({
	project,
	onChanged
}: {
	project: ProjectView;
	onChanged: () => void;
}) {
	const can = projectCan(project);
	const { query } = useRoute();
	const navigate = useNavigate();
	const feedback = useFeedback();
	const [groups, setGroups] = useState<ScopeOption[]>([]);
	const [moving, setMoving] = useState(false);
	const [deleting, setDeleting] = useState(false);
	const [heldClients, setHeldClients] = useState<string[]>([]);
	const [destroying, setDestroying] = useState(false);
	const scrolled = useRef(false);

	useEffect(() => {
		void (async () => {
			const result = await request<{ available: ScopeOption[] }>(
				'GET',
				'/admin/api/scope'
			);
			if (result.ok) setGroups(result.data.available);
		})();
	}, []);

	// A link to one card (`#bucket`) lands on it once the page is drawn.
	useEffect(() => {
		if (scrolled.current) return;
		scrolled.current = true;
		const id = window.location.hash.slice(1);
		if (id) document.getElementById(id)?.scrollIntoView({ block: 'start' });
	}, []);

	const group = groups.find((g) => g.id === project.ownerGroupId);
	const groupName = group ? groupLabel(group) : 'a group you are not in';
	const bucket = project.bucket ?? null;
	/* The Default bucket never moves, so a project on it moves alone (specs/098). */
	const movesAlone = project.bucketId === DEFAULT_BUCKET_ID;

	/*
	 * The clients are fetched rather than read off the project, because `clientIds` can hold an id whose
	 * client no longer exists — and an administrator must not be shown a ghost as something they are about
	 * to destroy. The server drops the same ids for the same reason.
	 */
	async function openDelete() {
		const result = await request<{ clientId: string }[]>(
			'GET',
			`/admin/api/projects/${encodeURIComponent(project._id)}/clients`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		setHeldClients(result.data.map((c) => c.clientId));
		setDeleting(true);
	}

	async function onDelete(withCascade: boolean) {
		setDestroying(true);
		const params = new URLSearchParams();
		if (withCascade) {
			params.set('cascade', 'clients');
			// The set the administrator just reviewed, so a client that arrived while they were reading is
			// refused rather than destroyed on the strength of their consent.
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
			feedback.failed(result);
			return;
		}
		const clients = result.data.clientsDestroyed ?? 0;
		const resources = result.data.resourcesRemoved ?? 0;
		feedback.done(
			`Project ${project.name} deleted, with ${plural(clients, 'client', 'clients')} and ${plural(resources, 'resource declaration', 'resource declarations')}.`
		);
		setDeleting(false);
		void navigate('/admin/projects', { replace: true });
	}

	async function afterMove() {
		setMoving(false);
		const check = await request(
			'GET',
			`/admin/api/projects/${encodeURIComponent(project._id)}`
		);
		if (!check.ok && (check.status === 403 || check.status === 404)) {
			feedback.done(
				`${project.name} now belongs to a group you are not in, so it left your list.`
			);
			void navigate('/admin/projects', { replace: true });
			return;
		}
		onChanged();
	}

	return (
		<Flex
			vertical
			gap={16}
		>
			<GeneralCard
				project={project}
				canEdit={can.edit}
				onChanged={onChanged}
			/>
			<BucketCard
				project={project}
				canAssign={can.assignBucket}
				preselect={query.get('bucket') ?? undefined}
				onChanged={onChanged}
			/>
			<Card
				id="ownership"
				title="Ownership"
			>
				<Flex
					vertical
					gap={8}
				>
					<Flex
						justify="space-between"
						align="center"
						wrap
						gap={12}
					>
						<Typography.Text>
							Owned by <Typography.Text strong>{groupName}</Typography.Text>
						</Typography.Text>
						{can.move && movesAlone && (
							<Button onClick={() => setMoving(true)}>
								Move to another group…
							</Button>
						)}
					</Flex>
					{!movesAlone && bucket && (
						<Typography.Text type="secondary">
							A project and its bucket always share a group, so this project
							moves with its bucket.{' '}
							<Link href={bucketHref(bucket.id, 'settings')}>
								Move the bucket…
							</Link>
						</Typography.Text>
					)}
				</Flex>
			</Card>
			{can.delete && (
				<Card
					id="danger"
					title="Danger zone"
					styles={{ header: { color: 'var(--ant-color-error)' } }}
				>
					<Flex
						justify="space-between"
						align="center"
						wrap
						gap={12}
					>
						<div>
							<Typography.Text strong>Delete project</Typography.Text>
							<br />
							<Typography.Text type="secondary">
								The project, and with your separate consent its clients, are
								destroyed. Its bucket and the people in it are untouched.
							</Typography.Text>
						</div>
						<Button
							danger
							onClick={() => void openDelete()}
						>
							Delete project…
						</Button>
					</Flex>
				</Card>
			)}
			{moving && (
				<MoveToGroup
					kind="project"
					id={project._id}
					name={project.name}
					sourceGroupId={project.ownerGroupId}
					onClose={() => setMoving(false)}
					onMoved={() => void afterMove()}
				/>
			)}
			{deleting && (
				<ConfirmDestruction
					open
					title={`Delete ${project.name}?`}
					word={ACTIONS['project.delete'].word}
					consequences={[
						'The project is gone permanently. There is nothing left to inspect or restore.',
						'Every protected resource it declared stops being served.',
						// Said, because "delete the project" reads as if it might take the bucket with it.
						bucket
							? `Its bucket (${bucket.name}) is untouched — buckets are shared and outlive projects.`
							: 'No bucket is affected.'
					]}
					cascade={
						heldClients.length > 0
							? {
									noun: 'clients',
									count: heldClients.length,
									onInspect: () => {
										setDeleting(false);
										void navigate(projectHref(project._id, 'clients'));
									},
									inspectLabel: `Look at them first (${heldClients.join(', ')})`
								}
							: undefined
					}
					busy={destroying}
					onCancel={() => setDeleting(false)}
					onConfirm={(withCascade) => void onDelete(withCascade)}
				/>
			)}
		</Flex>
	);
}
