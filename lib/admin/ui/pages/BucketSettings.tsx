import { useState } from 'react';
import {
	Alert,
	Badge,
	Button,
	Card,
	Descriptions,
	Flex,
	Form,
	Input,
	Segmented,
	Space,
	Typography
} from 'antd';
import { isUndeletableBucket } from '../../consts.js';
import { MoveToGroup } from '../MoveToGroup.js';
import type { BucketCan } from '../frame/can.js';
import { useFeedback } from '../frame/feedback.js';
import { meCan, useMe } from '../frame/me.js';
import { PreviewConfirm, type PreviewStep } from '../frame/PreviewConfirm.js';
import { request } from '../frame/request.js';
import { Link, useLeaveGuard, useNavigate } from '../frame/router.js';
import { bucketHref } from '../frame/routes.js';
import { DeleteBucketDialog } from './DeleteBucketDialog.js';
import { useScheduledActions } from './ScheduledBanner.js';
import type { AddressPreview, BucketView } from './bucketView.js';

/*
 * A bucket's own properties (specs/081): its name, its address, the group that owns it, and — at the foot,
 * apart from everything an operator does daily — the two acts that break things. Each section commits on its
 * own: renaming is one save, a move and an address change are previewed by the server first, a deletion
 * asks for the typed word.
 */

const FORM_LABEL: Record<NonNullable<BucketView['addressForm']>, string> = {
	root: "Served at the server's root",
	path: 'A path of the server',
	host: 'A hostname of its own',
	unaddressed: 'No address of its own'
};

function plural(n: number, one: string, many: string): string {
	return `${String(n)} ${n === 1 ? one : many}`;
}

interface GeneralValues {
	name: string;
	displayName: string;
}

export function GeneralCard({
	bucket,
	canEdit,
	onChanged
}: {
	bucket: BucketView;
	canEdit: boolean;
	onChanged: () => void;
}) {
	const feedback = useFeedback();
	const [form] = Form.useForm<GeneralValues>();
	// Undefined until the form mounts, whatever the field's type says.
	const name = Form.useWatch('name', form) as string | undefined;
	const displayName = Form.useWatch('displayName', form) as string | undefined;
	const [saving, setSaving] = useState(false);
	const initial: GeneralValues = {
		name: bucket.name,
		displayName: bucket.displayName ?? ''
	};
	const dirty =
		(name !== undefined && name !== initial.name) ||
		(displayName !== undefined && displayName !== initial.displayName);
	useLeaveGuard(dirty, dirty ? 1 : 0);

	async function save(values: GeneralValues) {
		setSaving(true);
		const shown = values.displayName.trim();
		const result = await request(
			'PATCH',
			`/admin/api/projects/${encodeURIComponent(bucket._id)}`,
			// Emptied means removed: the pages then show the bucket's address.
			{ name: values.name, displayName: shown ? shown : null }
		);
		setSaving(false);
		if (!result.ok) {
			feedback.failed(result, form);
			return;
		}
		feedback.done('Project saved.');
		onChanged();
	}

	return (
		<Card title="General">
			<Form
				form={form}
				layout="vertical"
				initialValues={initial}
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
				<Form.Item
					name="displayName"
					label="Name shown to users"
					extra="What people see at the top of the page where they allow an app access — for example “Acme ID”. Leave it empty to show the project’s address instead. The name above is only for this console."
				>
					<Input
						style={{ maxWidth: 420 }}
						maxLength={60}
						placeholder="the project’s address"
					/>
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
							onClick={() => form.setFieldsValue(initial)}
						>
							Reset
						</Button>
					</Space>
				)}
			</Form>
		</Card>
	);
}

function AddressCard({ bucket }: { bucket: BucketView }) {
	const address = bucket.address;
	return (
		<Card title="Address">
			<Descriptions
				column={1}
				size="small"
				items={[
					{
						key: 'form',
						label: 'Form',
						children: bucket.addressForm ? FORM_LABEL[bucket.addressForm] : '—'
					},
					{
						key: 'issuer',
						label: 'Issuer URL',
						children: bucket.issuer ? (
							<Typography.Text
								code
								copyable
							>
								{bucket.issuer}
							</Typography.Text>
						) : (
							<Typography.Text type="secondary">None</Typography.Text>
						)
					},
					...(address
						? [
								{
									key: 'dns',
									label: 'DNS record',
									children: (
										<Space wrap>
											<Typography.Text code>
												{address.dnsRecord.name}
											</Typography.Text>
											<Typography.Text>
												{address.dnsRecord.type}
											</Typography.Text>
											<Typography.Text
												code
												copyable
											>
												{address.dnsRecord.value}
											</Typography.Text>
										</Space>
									)
								},
								{
									key: 'status',
									label: 'Requests',
									children: address.requestsArrived ? (
										<Badge
											status="success"
											text="Requests are arriving"
										/>
									) : (
										<Badge
											status="warning"
											text={`No request has reached ${address.host} yet`}
										/>
									)
								}
							]
						: [])
				]}
			/>
			{address?.stillToDo && (
				<Alert
					style={{ marginTop: 12 }}
					type="info"
					showIcon
					title={address.stillToDo}
				/>
			)}
		</Card>
	);
}

/* What the change affects, as the server listed it (data-model §6). */
function AddressPreviewView({ preview }: { preview: AddressPreview }) {
	const none =
		preview.applications.length +
			preview.connections.length +
			preview.providers.length +
			preview.resources.length ===
		0;
	return (
		<Flex
			vertical
			gap={8}
			style={{ marginTop: 12 }}
		>
			<Typography.Text>
				From <Typography.Text code>{preview.from}</Typography.Text> to{' '}
				<Typography.Text code>{preview.to}</Typography.Text>
			</Typography.Text>
			{none ? (
				<Typography.Text type="secondary">
					Nothing else is affected.
				</Typography.Text>
			) : (
				<>
					{preview.applications.length > 0 && (
						<div>
							<Typography.Text strong>
								Applications that must be reconfigured
							</Typography.Text>
							<ul style={{ margin: 0 }}>
								{preview.applications.map((a) => (
									<li key={a.clientId}>{a.name ?? a.clientId}</li>
								))}
							</ul>
						</div>
					)}
					{preview.connections.length > 0 && (
						<div>
							<Typography.Text strong>Provisioning connections</Typography.Text>
							<ul style={{ margin: 0 }}>
								{preview.connections.map((c) => (
									<li key={c.id}>{c.displayName}</li>
								))}
							</ul>
						</div>
					)}
					{preview.providers.length > 0 && (
						<div>
							<Typography.Text strong>
								Identity providers: register the new callback address
							</Typography.Text>
							<ul style={{ margin: 0 }}>
								{preview.providers.map((p) => (
									<li key={p.id}>
										{p.displayName}:{' '}
										<Typography.Text
											code
											copyable
										>
											{p.newCallback}
										</Typography.Text>
									</li>
								))}
							</ul>
						</div>
					)}
					{preview.resources.length > 0 && (
						<div>
							<Typography.Text strong>Declared resources</Typography.Text>
							<ul style={{ margin: 0 }}>
								{preview.resources.map((r) => (
									<li key={r.identifier}>
										{r.identifier} — {r.name}
									</li>
								))}
							</ul>
						</div>
					)}
				</>
			)}
			{preview.namespaceMove && (
				<Typography.Text type="secondary">
					The project's API declarations move with it.
				</Typography.Text>
			)}
			<Alert
				type="warning"
				showIcon
				title={preview.consequence}
			/>
		</Flex>
	);
}

function ChangeAddressDialog({
	bucket,
	onClose,
	onChanged
}: {
	bucket: BucketView;
	onClose: () => void;
	onChanged: () => void;
}) {
	const { me } = useMe();
	const mayHost = meCan(me).createHost;
	const [form, setForm] = useState<'path' | 'host'>(
		bucket.addressForm === 'host' && mayHost ? 'host' : 'path'
	);
	const [value, setValue] = useState('');
	const [preview, setPreview] = useState<AddressPreview | null>(null);
	const [moved, setMoved] = useState(false);

	async function step(commit: boolean): Promise<PreviewStep<AddressPreview>> {
		const target =
			form === 'host' ? { host: value.trim() } : { slug: value.trim() };
		const result = await request<{ to?: string }>(
			'POST',
			`/admin/api/projects/${encodeURIComponent(bucket._id)}/address`,
			commit && preview
				? { ...target, confirm: true, expect: preview.expect }
				: target
		);
		if (result.ok) {
			return {
				kind: 'done',
				text: `Address changed to ${result.data.to ?? value}.`
			};
		}
		if (result.status === 409 && result.error.confirmationRequired === true) {
			// A second preview after a commit means the set changed in between: shown, never applied silently.
			setMoved(commit);
			return {
				kind: 'preview',
				preview: result.error as unknown as AddressPreview
			};
		}
		return { kind: 'failed', result };
	}

	return (
		<PreviewConfirm<AddressPreview>
			open
			title={`Change the address of ${bucket.name}`}
			commitText="Change address"
			danger
			ready={value.trim().length > 0}
			preview={preview}
			onPreview={setPreview}
			step={step}
			renderPreview={(p) => (
				<>
					{moved && (
						<Alert
							style={{ marginTop: 12 }}
							type="warning"
							showIcon
							title="What this change affects has changed since you reviewed it. Review it again."
						/>
					)}
					<AddressPreviewView preview={p} />
				</>
			)}
			onClose={onClose}
			onDone={onChanged}
		>
			<Flex
				vertical
				gap={12}
			>
				{mayHost && (
					<Segmented
						value={form}
						options={[
							{ label: 'Path', value: 'path' },
							{ label: 'Hostname', value: 'host' }
						]}
						onChange={(next) => {
							setForm(next as 'path' | 'host');
							setPreview(null);
						}}
					/>
				)}
				<Input
					autoFocus
					prefix={form === 'path' ? '/' : 'https://'}
					placeholder={form === 'path' ? 'acme' : 'login.acme.com'}
					value={value}
					onChange={(event) => {
						setValue(event.target.value);
						setPreview(null);
						setMoved(false);
					}}
				/>
			</Flex>
		</PreviewConfirm>
	);
}

export function BucketSettings({
	bucket,
	can,
	groupName,
	onChanged
}: {
	bucket: BucketView;
	can: BucketCan;
	groupName: string;
	onChanged: () => void;
}) {
	const { me } = useMe();
	const feedback = useFeedback();
	const navigate = useNavigate();
	const [moving, setMoving] = useState(false);
	const [changingAddress, setChangingAddress] = useState(false);
	const [deleting, setDeleting] = useState(false);
	const scheduled = useScheduledActions({
		onRestored: onChanged,
		onDeleted: () => void navigate('/admin/projects', { replace: true })
	});
	const fixed = isUndeletableBucket(bucket._id);
	const holdsApplications = bucket.applications ?? 0;
	const holdsApis = bucket.apis ?? 0;
	const dependents = bucket.blockers?.dependents;
	const ownsGroup = (me?.memberships ?? []).some(
		(m) => m.teamId === bucket.ownerTeamId && m.role === 'owner'
	);

	/*
	 * A group owner is told why the address is out of reach once something depends on the bucket; a member,
	 * who could never change it, is not shown the act at all.
	 */
	const addressReason =
		!can.changeAddress && !bucket.deletion && ownsGroup && dependents
			? `Used by ${plural(dependents.applications, 'application', 'applications')}, ${plural(dependents.providers, 'identity provider', 'identity providers')} and ${plural(dependents.connections, 'provisioning connection', 'provisioning connections')}: only an instance administrator can change this project's address now.`
			: null;

	async function afterMove() {
		setMoving(false);
		const check = await request(
			'GET',
			`/admin/api/projects/${encodeURIComponent(bucket._id)}`
		);
		if (!check.ok && (check.status === 403 || check.status === 404)) {
			feedback.done(
				`${bucket.name} now belongs to a team you are not in, so it left your list.`
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
				bucket={bucket}
				canEdit={can.editSettings}
				onChanged={onChanged}
			/>
			<AddressCard bucket={bucket} />
			<Card title="Ownership">
				<Flex
					justify="space-between"
					align="center"
					wrap
					gap={12}
				>
					<Typography.Text>
						Owned by <Typography.Text strong>{groupName}</Typography.Text>
					</Typography.Text>
					{can.move && !fixed && (
						<Button onClick={() => setMoving(true)}>Move to team…</Button>
					)}
				</Flex>
			</Card>

			{!fixed && (can.changeAddress || addressReason || can.delete) && (
				<Card
					title="Danger zone"
					styles={{ header: { color: 'var(--ant-color-error)' } }}
				>
					<Flex
						vertical
						gap={16}
					>
						{(can.changeAddress || addressReason) && (
							<Flex
								justify="space-between"
								align="center"
								wrap
								gap={12}
							>
								<div>
									<Typography.Text strong>Change address</Typography.Text>
									<br />
									<Typography.Text type="secondary">
										{addressReason ??
											'Applications using this project must be reconfigured with the new issuer.'}
									</Typography.Text>
								</div>
								<Button
									danger
									disabled={!can.changeAddress}
									onClick={() => setChangingAddress(true)}
								>
									Change address…
								</Button>
							</Flex>
						)}
						{can.delete && bucket.deletion && (
							<Flex
								justify="space-between"
								align="center"
								wrap
								gap={12}
							>
								<div>
									<Typography.Text strong>
										Scheduled for deletion
									</Typography.Text>
									<br />
									<Typography.Text type="secondary">
										Deleted permanently on{' '}
										{new Date(bucket.deletion.purgeAt).toLocaleDateString()}{' '}
										unless it is restored.
									</Typography.Text>
								</div>
								<Space>
									<Button onClick={() => void scheduled.restore(bucket)}>
										Restore
									</Button>
									<Button
										danger
										onClick={() => scheduled.deleteNow(bucket)}
									>
										Delete now…
									</Button>
								</Space>
							</Flex>
						)}
						{can.delete && !bucket.deletion && (
							<Flex
								justify="space-between"
								align="center"
								wrap
								gap={12}
							>
								<div>
									<Typography.Text strong>Delete project</Typography.Text>
									<br />
									{holdsApplications + holdsApis > 0 ? (
										<Typography.Text type="secondary">
											It still holds{' '}
											<Link href={bucketHref(bucket._id, 'applications')}>
												{plural(
													holdsApplications,
													'application',
													'applications'
												)}
											</Link>{' '}
											and{' '}
											<Link href={bucketHref(bucket._id, 'apis')}>
												{plural(holdsApis, 'API', 'APIs')}
											</Link>{' '}
											— delete them first.
										</Typography.Text>
									) : (
										<Typography.Text type="secondary">
											It stops answering at once and is destroyed after 30 days,
											with its accounts if you consent. Until then it can be
											restored.
										</Typography.Text>
									)}
								</div>
								<Button
									danger
									disabled={holdsApplications + holdsApis > 0}
									onClick={() => setDeleting(true)}
								>
									Delete project…
								</Button>
							</Flex>
						)}
					</Flex>
				</Card>
			)}

			{moving && (
				<MoveToGroup
					id={bucket._id}
					name={bucket.name}
					sourceGroupId={bucket.ownerTeamId}
					onClose={() => setMoving(false)}
					onMoved={() => void afterMove()}
				/>
			)}
			{changingAddress && (
				<ChangeAddressDialog
					bucket={bucket}
					onClose={() => setChangingAddress(false)}
					onChanged={() => {
						setChangingAddress(false);
						onChanged();
					}}
				/>
			)}
			{deleting && (
				<DeleteBucketDialog
					bucket={bucket}
					onClose={() => setDeleting(false)}
					onDeleted={({ purgeAt }) => {
						setDeleting(false);
						feedback.done(
							purgeAt
								? `Scheduled for deletion on ${new Date(purgeAt).toLocaleDateString()}.`
								: `Project ${bucket.name} scheduled for deletion.`
						);
						onChanged();
					}}
				/>
			)}
			{scheduled.dialog}
		</Flex>
	);
}
