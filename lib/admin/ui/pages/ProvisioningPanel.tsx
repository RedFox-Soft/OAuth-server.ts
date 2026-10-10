import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Descriptions,
	Drawer,
	Form,
	Input,
	InputNumber,
	Modal,
	Radio,
	Select,
	Space,
	Switch,
	Table,
	Tag,
	Tooltip,
	Typography
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { FederationProvider } from '../../../federation/types.js';
import type {
	ConnectionView,
	ConnectionWarning
} from '../../../provisioning/service.js';
import { ConfirmDestruction } from '../ConfirmDestruction.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import { Blocked } from '../frame/rights.js';
import { EmptyState, LoadFailed } from '../frame/states.js';

export type { ConnectionView };

/*
 * A bucket's SCIM provisioning connections: the directory (Entra ID, Okta, …) that creates, changes and
 * removes this bucket's people, and the credential it authenticates with.
 *
 * Its own component for FederationPanel's reason: BucketDetail is the per-bucket user surface and long
 * enough. The list is handed up through `onConnections`, because the user table beside it names the
 * connection that manages each person and offers to hand a local user to one.
 */

/*
 * Short and stated as the cause an administrator can act on, not as the server's code: each one is a reason
 * the directory's requests will be refused even though the connection looks configured.
 */
const WARNING_LABELS: Record<ConnectionWarning, string> = {
	scim_disabled: 'SCIM is switched off in Settings',
	bucket_unaddressed: 'Bucket has no address yet',
	provider_disabled: 'Sign-in provider is disabled',
	client_credentials_disabled: 'Client-credentials grant is off',
	credential_kind_disabled: 'This credential kind is switched off'
};

interface CreateValues {
	displayName: string;
	providerId: string;
	correlationClaim?: string;
	correlationAttribute?: 'externalId' | 'userName';
	emailTrust: 'trusted' | 'untrusted';
}

interface KeyValues {
	source: 'jwks' | 'jwksUri';
	jwksText?: string;
	jwksUri?: string;
	signingAlg?: string;
}

/* Which value the one-time reveal is holding, so its warning names the thing being copied. */
interface Revealed {
	noun: 'secret' | 'token';
	value: string;
}

const ATTRIBUTE_OPTIONS = [
	{ label: 'externalId', value: 'externalId' },
	{ label: 'userName', value: 'userName' }
];

/*
 * Parsed here only to refuse what is not a key set before a round trip; whether the keys are public,
 * asymmetric and usable is the server's check, and its refusal is shown as is.
 */
function parseJwks(text: string | undefined): {
	keys: Record<string, unknown>[];
} {
	const value: unknown = JSON.parse(text?.trim() || 'null');
	if (
		typeof value !== 'object' ||
		value === null ||
		!Array.isArray((value as { keys?: unknown }).keys)
	) {
		throw new TypeError('paste a JSON Web Key Set: {"keys":[…]}');
	}
	return value as { keys: Record<string, unknown>[] };
}

function when(iso: string | null | undefined): string {
	return iso ? new Date(iso).toLocaleString() : 'never';
}

/*
 * The guard's window, shown in the largest unit that states it exactly. The server takes seconds; an
 * administrator thinks in minutes, hours or days, so the picker offers those and the bounds are said in them.
 */
const WINDOW_UNITS = [
	{ label: 'minutes', value: 60 },
	{ label: 'hours', value: 3600 },
	{ label: 'days', value: 86400 }
];
const MIN_WINDOW_SECONDS = 300;
const MAX_WINDOW_SECONDS = 604800;

function windowParts(seconds: number): { amount: number; unit: number } {
	const unit =
		[...WINDOW_UNITS].reverse().find((u) => seconds % u.value === 0)?.value ??
		60;
	return { amount: seconds / unit, unit };
}

function describeWindow(seconds: number): string {
	const { amount, unit } = windowParts(seconds);
	const label = WINDOW_UNITS.find((u) => u.value === unit)?.label ?? 'minutes';
	return `${amount} ${amount === 1 ? label.replace(/s$/, '') : label}`;
}

interface GuardValues {
	on: boolean;
	count?: number;
	windowAmount?: number;
	windowUnit: number;
}

type Threshold = { count: number; windowSeconds: number };

/*
 * The mass-deprovisioning guard of one connection: off by default, and when turned on it suggests 500 within
 * one hour (specs/072 FR-017). Saving sends the whole threshold, or `null` to remove it — which the server
 * refuses while the connection is held, so a hold is only ever ended by the release beside it.
 */
function DeprovisioningGuard({
	connection,
	canEdit,
	onSave,
	onRelease
}: {
	connection: ConnectionView;
	canEdit: boolean;
	onSave: (threshold: Threshold | null) => Promise<boolean>;
	onRelease: () => void;
}) {
	const confirm = useConfirm();
	const [form] = Form.useForm<GuardValues>();
	const [saving, setSaving] = useState(false);
	const on = Form.useWatch('on', form);
	const current = connection.threshold;
	const held = connection.hold;
	const initial: GuardValues = current
		? {
				on: true,
				count: current.count,
				windowAmount: windowParts(current.windowSeconds).amount,
				windowUnit: windowParts(current.windowSeconds).unit
			}
		: { on: false, count: 500, windowAmount: 1, windowUnit: 3600 };

	async function submit(values: GuardValues) {
		/*
		 * Turning the guard off is the one save that takes a protection away, so it alone asks; any other
		 * save only changes how much the guard tolerates.
		 */
		const proceed =
			!values.on && current
				? await confirm('connection.guard.off', {
						target: connection.displayName,
						consequences: [
							'The directory can then deactivate or delete any number of people at once, and nothing holds it.'
						]
					})
				: await confirm('connection.guard.save', {
						target: connection.displayName
					});
		if (!proceed) return;
		setSaving(true);
		try {
			await onSave(
				values.on
					? {
							count: values.count ?? 500,
							windowSeconds: (values.windowAmount ?? 1) * values.windowUnit
						}
					: null
			);
		} finally {
			setSaving(false);
		}
	}

	return (
		<Space
			orientation="vertical"
			size="small"
			style={{ width: '100%' }}
		>
			<Typography.Title
				level={5}
				style={{ margin: 0 }}
			>
				Mass-deprovisioning guard
			</Typography.Title>
			{held && (
				<Alert
					type="error"
					showIcon
					title={`Held since ${when(held.since)}, after ${held.count} deprovisioning${held.count === 1 ? '' : 's'}`}
					description="Every deactivation and deletion from the directory is refused and retried later; creates and updates still go through. The people it is trying to remove keep their access until the hold is released."
					action={
						canEdit && (
							<Button
								size="small"
								danger
								onClick={onRelease}
							>
								Release hold…
							</Button>
						)
					}
				/>
			)}
			<Typography.Paragraph type="secondary">
				Holds the connection when the directory deactivates or deletes more
				people than this within the window, so a wrong rule in the directory
				cannot remove everyone. Off by default: while held, people the directory
				removes keep their access until an administrator releases the hold.
			</Typography.Paragraph>
			{canEdit && (
				<Form<GuardValues>
					form={form}
					layout="inline"
					initialValues={initial}
					scrollToFirstError
					onFinish={(values) => void submit(values)}
				>
					<Form.Item
						name="on"
						valuePropName="checked"
						tooltip={
							held && current
								? 'Release the hold before turning the guard off'
								: undefined
						}
					>
						<Switch
							aria-label="Mass-deprovisioning guard"
							disabled={held !== undefined && current !== undefined}
						/>
					</Form.Item>
					{on && (
						<>
							<Form.Item
								name="count"
								label="At most"
								rules={[{ required: true }]}
							>
								<InputNumber
									min={1}
									max={100000}
									precision={0}
									style={{ width: 110 }}
								/>
							</Form.Item>
							<Form.Item
								name="windowAmount"
								label="within"
								dependencies={['windowUnit']}
								rules={[
									{ required: true },
									({ getFieldValue }) => ({
										validator: async (_rule, amount: number | undefined) => {
											const seconds =
												(amount ?? 0) * Number(getFieldValue('windowUnit'));
											if (
												seconds < MIN_WINDOW_SECONDS ||
												seconds > MAX_WINDOW_SECONDS
											) {
												throw new Error('between 5 minutes and 7 days');
											}
										}
									})
								]}
							>
								<InputNumber
									min={1}
									precision={0}
									style={{ width: 80 }}
								/>
							</Form.Item>
							<Form.Item name="windowUnit">
								<Select
									options={WINDOW_UNITS}
									style={{ width: 110 }}
								/>
							</Form.Item>
						</>
					)}
					<Form.Item>
						<Button
							htmlType="submit"
							loading={saving}
						>
							Save
						</Button>
					</Form.Item>
				</Form>
			)}
			{current ? (
				<Typography.Text type="secondary">
					In force: at most {current.count} within{' '}
					{describeWindow(current.windowSeconds)}.
				</Typography.Text>
			) : (
				!canEdit && <Typography.Text type="secondary">Off.</Typography.Text>
			)}
		</Space>
	);
}

/* A value an administrator carries into somebody else's console, offered as one copy action. */
function Copyable({ value }: { value: string | null }) {
	return value === null ? (
		<Typography.Text type="secondary">
			not available until the bucket has an address
		</Typography.Text>
	) : (
		<Typography.Text
			code
			copyable={{ text: value }}
		>
			{value}
		</Typography.Text>
	);
}

export function ProvisioningPanel({
	bucketId,
	refreshKey,
	onConnections,
	onChanged,
	canEdit = true
}: {
	bucketId: string;
	/* Bumped by the parent when something this panel shows changed elsewhere — a provider, a user's owner. */
	refreshKey?: number;
	/* Must be stable (a state setter): it is a dependency of the fetch. */
	onConnections?: (connections: ConnectionView[]) => void;
	/*
	 * `created` is distinguished because creating a connection also closes its provider to just-in-time
	 * creation, so the providers list beside this panel is stale after it.
	 */
	onChanged?: (event: 'created' | 'changed' | 'deleted') => void;
	/* False when the caller may read this bucket but not change it; the server would refuse every write. */
	canEdit?: boolean;
}) {
	const bucketBase = `/admin/api/buckets/${encodeURIComponent(bucketId)}`;
	const base = `${bucketBase}/provisioning-connections`;
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [rows, setRows] = useState<ConnectionView[]>([]);
	const [providers, setProviders] = useState<FederationProvider[]>([]);
	const [loading, setLoading] = useState(true);
	const [loadFailure, setLoadFailure] = useState<string | null>(null);
	const [createOpen, setCreateOpen] = useState(false);
	const [saving, setSaving] = useState(false);
	const [setupId, setSetupId] = useState<string | null>(null);
	const [keyOpen, setKeyOpen] = useState(false);
	const [revealed, setRevealed] = useState<Revealed | null>(null);
	const [releasing, setReleasing] = useState<{
		connection: ConnectionView;
		/* The drawer it was opened from, reopened when the dialog closes. */
		returnTo: string | null;
	} | null>(null);
	const [createForm] = Form.useForm<CreateValues>();
	const [keyForm] = Form.useForm<KeyValues>();
	const keySource = Form.useWatch('source', keyForm);

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchConnections = useCallback(async () => {
		try {
			const [connections, federation] = await Promise.all([
				request<ConnectionView[]>('GET', base),
				request<FederationProvider[]>('GET', `${bucketBase}/federation`)
			]);
			/*
			 * Either half failing is a failed load: without the providers, "New connection" would say every
			 * provider already has one, which is a wrong answer rather than no answer.
			 */
			if (!connections.ok) {
				setLoadFailure(connections.error.message);
			} else if (!federation.ok) {
				setLoadFailure(federation.error.message);
			} else {
				setLoadFailure(null);
				setRows(connections.data);
				setProviders(federation.data);
				onConnections?.(connections.data);
			}
		} finally {
			setLoading(false);
		}
	}, [base, bucketBase, onConnections]);
	function load() {
		setLoading(true);
		return fetchConnections();
	}
	useEffect(() => {
		void fetchConnections();
	}, [fetchConnections, refreshKey]);

	/* Read from the list rather than held as a copy, so the drawer shows what the last reload returned. */
	const setup = rows.find((row) => row.id === setupId) ?? null;

	function closeSetup() {
		setSetupId(null);
		setKeyOpen(false);
		setRevealed(null);
	}

	async function changed(event: 'created' | 'changed' | 'deleted') {
		await load();
		onChanged?.(event);
	}

	async function onCreate(values: CreateValues) {
		setSaving(true);
		try {
			const claim = values.correlationClaim?.trim();
			const result = await request<ConnectionView>('POST', base, {
				displayName: values.displayName,
				providerId: values.providerId,
				emailTrust: values.emailTrust,
				...(claim && values.correlationAttribute
					? {
							correlation: {
								claim,
								attribute: values.correlationAttribute
							}
						}
					: {})
			});
			if (!result.ok) {
				feedback.failed(result, createForm);
				return;
			}
			const created = result.data;
			setCreateOpen(false);
			createForm.resetFields();
			feedback.done(
				`Provisioning connection ${created.displayName} created; ${created.providerId} now signs in existing accounts only.`
			);
			await changed('created');
			setSetupId(created.id);
		} finally {
			setSaving(false);
		}
	}

	async function saveThreshold(
		row: ConnectionView,
		threshold: Threshold | null
	): Promise<boolean> {
		const result = await request(
			'PATCH',
			`${base}/${encodeURIComponent(row.id)}`,
			{ threshold }
		);
		if (!result.ok) {
			feedback.failed(result);
			return false;
		}
		feedback.done(
			threshold
				? `Mass-deprovisioning guard of ${row.displayName} saved.`
				: `Mass-deprovisioning guard of ${row.displayName} turned off.`
		);
		await changed('changed');
		return true;
	}

	/*
	 * The release takes a typed word, and that dialog is never stacked on the drawer: the drawer closes
	 * while it is open and comes back when it closes, so the operator lands where they started.
	 */
	function startRelease(row: ConnectionView) {
		setReleasing({
			connection: row,
			returnTo: setupId === row.id ? row.id : null
		});
		closeSetup();
	}

	function endRelease() {
		if (releasing?.returnTo) setSetupId(releasing.returnTo);
		setReleasing(null);
	}

	async function release() {
		if (!releasing) return;
		const row = releasing.connection;
		setSaving(true);
		try {
			const result = await request(
				'POST',
				`${base}/${encodeURIComponent(row.id)}/release`
			);
			if (!result.ok) {
				feedback.failed(result);
				return;
			}
			feedback.done(
				`Hold on ${row.displayName} released; the directory's retries will go through.`
			);
			endRelease();
			await changed('changed');
		} finally {
			setSaving(false);
		}
	}

	async function setEnabled(row: ConnectionView, enabled: boolean) {
		const proceed = enabled
			? await confirm('connection.enable', { target: row.displayName })
			: await confirm('connection.disable', {
					target: row.displayName,
					consequences: [
						"The directory's requests are refused until it is enabled again, so the changes it makes to people do not reach this bucket.",
						...(row.managedUsers > 0
							? [
									`The ${row.managedUsers} user${row.managedUsers === 1 ? '' : 's'} it manages keep their accounts.`
								]
							: [])
					]
				});
		if (!proceed) return;
		const result = await request(
			'PATCH',
			`${base}/${encodeURIComponent(row.id)}`,
			{ enabled }
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(
			`Provisioning connection ${row.displayName} ${enabled ? 'enabled' : 'disabled'}.`
		);
		await changed('changed');
	}

	/*
	 * The OAuth credential is one slot, key or secret: issuing either replaces whichever is there, and every
	 * token the old one obtained is revoked with it. Said before the replacement is confirmed, because the
	 * directory that holds the old one stops working the moment it is.
	 */
	function replacing(
		row: ConnectionView,
		kind: 'oauth' | 'static_token'
	): string | null {
		if (kind === 'oauth') {
			return row.oauthCredential
				? `This replaces the current ${row.oauthCredential.kind} credential and revokes every token it obtained. The directory stops working until it is given the new one.`
				: null;
		}
		return row.staticToken
			? 'This replaces the current static token, which stops working immediately. The directory stops working until it is given the new one.'
			: null;
	}

	/* Issuing into an empty slot takes nothing away, so only a replacement asks. */
	async function confirmIssue(
		row: ConnectionView,
		kind: 'oauth' | 'static_token'
	): Promise<boolean> {
		const replaces = replacing(row, kind);
		if (replaces === null) return true;
		return confirm('connection.credential.issue', {
			target: row.displayName,
			consequences: [replaces]
		});
	}

	async function issue(
		row: ConnectionView,
		body:
			| { kind: 'secret' }
			| { kind: 'static_token' }
			| {
					kind: 'key';
					jwks?: { keys: Record<string, unknown>[] };
					jwksUri?: string;
					signingAlg?: string;
			  }
	): Promise<boolean> {
		const result = await request<{
			connection: ConnectionView;
			secret?: string;
			token?: string;
		}>('POST', `${base}/${encodeURIComponent(row.id)}/credentials`, body);
		if (!result.ok) {
			feedback.failed(result);
			return false;
		}
		const issued = result.data;
		if (issued.secret) setRevealed({ noun: 'secret', value: issued.secret });
		if (issued.token) setRevealed({ noun: 'token', value: issued.token });
		feedback.done(
			body.kind === 'key'
				? `Key credential issued for ${row.displayName}.`
				: body.kind === 'secret'
					? `Secret issued for ${row.displayName}.`
					: `Static token issued for ${row.displayName}.`
		);
		await changed('changed');
		return true;
	}

	async function issueSimple(
		row: ConnectionView,
		kind: 'secret' | 'static_token'
	) {
		if (
			!(await confirmIssue(row, kind === 'secret' ? 'oauth' : 'static_token'))
		) {
			return;
		}
		await issue(row, { kind });
	}

	async function onIssueKey(values: KeyValues) {
		if (!setup) return;
		if (!(await confirmIssue(setup, 'oauth'))) return;
		setSaving(true);
		try {
			const signingAlg = values.signingAlg?.trim();
			const ok = await issue(setup, {
				kind: 'key',
				...(values.source === 'jwks'
					? { jwks: parseJwks(values.jwksText) }
					: { jwksUri: values.jwksUri?.trim() }),
				...(signingAlg ? { signingAlg } : {})
			});
			if (!ok) return;
			setKeyOpen(false);
			keyForm.resetFields();
		} finally {
			setSaving(false);
		}
	}

	async function revoke(row: ConnectionView, kind: 'oauth' | 'static_token') {
		if (
			!(await confirm('connection.credential.revoke', {
				target: row.displayName,
				consequences: [
					kind === 'oauth'
						? 'Every token it obtained is revoked and the directory can no longer authenticate with it.'
						: 'The directory can no longer authenticate with it.'
				]
			}))
		) {
			return;
		}
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(row.id)}/credentials/${kind}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(
			kind === 'oauth'
				? `OAuth credential of ${row.displayName} revoked.`
				: `Static token of ${row.displayName} revoked.`
		);
		await changed('changed');
	}

	async function remove(row: ConnectionView) {
		if (
			!(await confirm('connection.delete', {
				target: row.displayName,
				consequences: [
					'The directory can no longer provision this bucket, and every token it holds is revoked.',
					'Its identity provider stays on this bucket, still limited to existing accounts.'
				]
			}))
		) {
			return;
		}
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(row.id)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`Provisioning connection ${row.displayName} deleted.`);
		if (setupId === row.id) closeSetup();
		await changed('deleted');
	}

	function actionsFor(row: ConnectionView): RowAction[] {
		const items: RowAction[] = [
			{
				key: 'edit',
				label: 'Edit…',
				group: 'edit',
				onClick: () => setSetupId(row.id)
			},
			row.enabled
				? {
						key: 'disable',
						label: 'Disable…',
						group: 'state',
						onClick: () => void setEnabled(row, false)
					}
				: {
						key: 'enable',
						label: 'Enable',
						group: 'state',
						onClick: () => void setEnabled(row, true)
					}
		];
		if (row.hold) {
			items.push({
				key: 'release',
				label: 'Release hold…',
				group: 'state',
				onClick: () => startRelease(row)
			});
		}
		items.push({
			key: 'delete',
			label: 'Delete…',
			group: 'danger',
			/* Refused by the server while it manages anyone, because people must never be removed or
			 * released as a side effect of deleting configuration. */
			blocked:
				row.managedUsers > 0
					? `Manages ${row.managedUsers} user${row.managedUsers === 1 ? '' : 's'} — disable it instead, or remove them through the directory first`
					: null,
			onClick: () => void remove(row)
		});
		return items;
	}

	/* A provider holds at most one connection, so the select never offers one the server would refuse. */
	const bound = new Set(rows.map((row) => row.providerId));
	const providerOptions = providers
		.filter((p) => !bound.has(p.id))
		.map((p) => ({
			label: `${p.displayName} (${p.id})`,
			value: p.id
		}));

	return (
		<div style={{ marginTop: 32 }}>
			<Space
				style={{ marginBottom: 12 }}
				align="center"
			>
				<Typography.Title
					level={4}
					style={{ margin: 0 }}
				>
					Provisioning (SCIM)
				</Typography.Title>
				{canEdit && (
					<Blocked
						reason={
							!loading && loadFailure === null && providerOptions.length === 0
								? 'Every identity provider on this bucket already has a connection — add a provider first'
								: null
						}
					>
						<Button
							icon={<PlusOutlined />}
							disabled={loading || loadFailure !== null}
							onClick={() => {
								createForm.resetFields();
								setCreateOpen(true);
							}}
						>
							New connection
						</Button>
					</Blocked>
				)}
			</Space>

			<Typography.Paragraph type="secondary">
				A connection lets a directory create, update and remove this bucket's
				users. Each one is bound to an identity provider above, which then signs
				in existing accounts only, so a person is never created twice.
			</Typography.Paragraph>

			{!canEdit && (
				<Alert
					style={{ marginBottom: 12 }}
					type="info"
					showIcon
					title="Only members of the group that owns this bucket can change this."
				/>
			)}

			{loadFailure !== null ? (
				<LoadFailed
					reason={loadFailure}
					onRetry={() => void load()}
				/>
			) : (
				<Table<ConnectionView>
					rowKey="id"
					loading={loading}
					dataSource={rows}
					pagination={false}
					locale={{
						emptyText: (
							<EmptyState purpose="No provisioning connections yet. No directory creates or removes this bucket's users." />
						)
					}}
					columns={[
						{
							title: 'Name',
							dataIndex: 'displayName',
							render: (name: string, row) => (
								<Space size={4}>
									<Typography.Link onClick={() => setSetupId(row.id)}>
										{name}
									</Typography.Link>
									{row.hold && (
										<Tooltip
											title={`Mass-deprovisioning guard tripped ${when(row.hold.since)} — open the connection to release the hold`}
										>
											<Tag color="red">Deprovisioning held</Tag>
										</Tooltip>
									)}
								</Space>
							)
						},
						{ title: 'Provider', dataIndex: 'providerId' },
						{
							title: 'Status',
							dataIndex: 'enabled',
							render: (enabled: boolean) => (
								<Tag color={enabled ? 'green' : 'default'}>
									{enabled ? 'Enabled' : 'Disabled'}
								</Tag>
							)
						},
						{ title: 'Managed users', dataIndex: 'managedUsers' },
						{
							title: 'Last used',
							dataIndex: 'lastUsedAt',
							render: (value: string | null) => when(value)
						},
						{
							title: 'Warnings',
							dataIndex: 'warnings',
							render: (warnings: ConnectionWarning[]) =>
								warnings.length === 0 ? (
									<Typography.Text type="secondary">—</Typography.Text>
								) : (
									<Space
										size={4}
										wrap
									>
										{warnings.map((w) => (
											<Tag
												key={w}
												color="orange"
											>
												{WARNING_LABELS[w]}
											</Tag>
										))}
									</Space>
								)
						},
						...(canEdit
							? [
									{
										title: '',
										key: 'actions',
										render: (_: unknown, row: ConnectionView) => (
											<RowActions
												name={row.displayName}
												items={actionsFor(row)}
											/>
										)
									}
								]
							: [])
					]}
				/>
			)}

			<Modal
				title="New provisioning connection"
				open={createOpen}
				onCancel={() => setCreateOpen(false)}
				onOk={() => createForm.submit()}
				confirmLoading={saving}
				destroyOnHidden
			>
				<Form<CreateValues>
					form={createForm}
					layout="vertical"
					onFinish={onCreate}
					scrollToFirstError
					initialValues={{ emailTrust: 'untrusted' }}
				>
					<Form.Item
						name="displayName"
						label="Name"
						rules={[{ required: true, max: 100 }]}
					>
						<Input placeholder="Acme Entra ID" />
					</Form.Item>
					<Form.Item
						name="providerId"
						label="Identity provider"
						tooltip="The provider these people sign in with. It is switched to existing accounts only, so a first sign-in never races the directory's own create."
						rules={[{ required: true }]}
					>
						<Select options={providerOptions} />
					</Form.Item>
					<Typography.Paragraph type="secondary">
						Correlation links a sign-in to the provisioned account. Leave it
						empty for the default: <Typography.Text code>oid</Typography.Text> ↔{' '}
						<Typography.Text code>externalId</Typography.Text> for Microsoft,{' '}
						<Typography.Text code>preferred_username</Typography.Text> ↔{' '}
						<Typography.Text code>userName</Typography.Text> for anything else.
					</Typography.Paragraph>
					<div style={{ display: 'flex', gap: 12 }}>
						<Form.Item
							name="correlationClaim"
							label="ID token claim"
							style={{ flex: 1 }}
							rules={[
								{
									pattern: /^[A-Za-z0-9_.:-]{1,64}$/,
									message: 'letters, digits and _ . : - only'
								}
							]}
						>
							<Input
								autoComplete="off"
								placeholder="default"
							/>
						</Form.Item>
						<Form.Item
							name="correlationAttribute"
							label="SCIM attribute"
							style={{ width: 180 }}
							dependencies={['correlationClaim']}
							rules={[
								({ getFieldValue }) => ({
									validator: async (_rule, value: string | undefined) => {
										const claim = (
											getFieldValue('correlationClaim') as string | undefined
										)?.trim();
										if (claim && !value) {
											throw new Error('choose the attribute the claim matches');
										}
									}
								})
							]}
						>
							<Select
								allowClear
								options={ATTRIBUTE_OPTIONS}
								placeholder="default"
							/>
						</Form.Item>
					</div>
					<Form.Item
						name="emailTrust"
						label="Email addresses from the directory"
						extra="Trusted marks the directory's addresses verified."
					>
						<Select
							options={[
								{ label: 'Untrusted', value: 'untrusted' },
								{ label: 'Trusted', value: 'trusted' }
							]}
						/>
					</Form.Item>
				</Form>
			</Modal>

			<Drawer
				size={640}
				open={setup !== null}
				onClose={closeSetup}
				title={setup ? `Provisioning connection ${setup.displayName}` : ''}
			>
				{setup ? (
					<Space
						orientation="vertical"
						size="middle"
						style={{ width: '100%' }}
					>
						{setup.warnings.length > 0 && (
							<Alert
								type="warning"
								showIcon
								title="The directory's requests will be refused until this is fixed"
								description={
									<ul style={{ margin: 0, paddingInlineStart: 20 }}>
										{setup.warnings.map((w) => (
											<li key={w}>{WARNING_LABELS[w]}</li>
										))}
									</ul>
								}
							/>
						)}
						<Descriptions
							column={1}
							size="small"
							bordered
						>
							<Descriptions.Item label="SCIM base URL">
								<Copyable value={setup.scimBaseUrl} />
							</Descriptions.Item>
							<Descriptions.Item label="Token endpoint">
								<Copyable value={setup.tokenEndpoint} />
							</Descriptions.Item>
							<Descriptions.Item label="Client id">
								<Copyable value={setup.clientId} />
							</Descriptions.Item>
							<Descriptions.Item label="Scope">
								<Copyable value={setup.scope} />
							</Descriptions.Item>
							<Descriptions.Item label="Metadata URL">
								<Copyable value={setup.metadataUrl} />
							</Descriptions.Item>
							<Descriptions.Item label="Correlation">
								<Typography.Text code>
									{setup.correlation.claim}
								</Typography.Text>{' '}
								↔{' '}
								<Typography.Text code>
									{setup.correlation.attribute}
								</Typography.Text>
							</Descriptions.Item>
							<Descriptions.Item label="Email addresses">
								{setup.emailTrust}
							</Descriptions.Item>
						</Descriptions>

						<Typography.Paragraph type="secondary">
							For Microsoft Entra ID, choose{' '}
							<strong>OAuth2 client credentials</strong> and issue a secret. For
							Okta, issue a static token and send it in the{' '}
							<Typography.Text code>Authorization</Typography.Text> header.
						</Typography.Paragraph>

						<Typography.Title
							level={5}
							style={{ margin: 0 }}
						>
							Credentials
						</Typography.Title>
						{/*
						 * Shown in the drawer rather than in a dialog over it: the value exists only in this
						 * answer, and a second layer on the drawer is one the operator can close by reflex.
						 */}
						{revealed && (
							<Alert
								type="warning"
								showIcon
								title={`Copy this ${revealed.noun} now — it will not be shown again.`}
								description={
									<Typography.Paragraph
										copyable
										code
										style={{ marginBottom: 0 }}
									>
										{revealed.value}
									</Typography.Paragraph>
								}
								action={
									<Button
										size="small"
										onClick={() => setRevealed(null)}
									>
										Done
									</Button>
								}
							/>
						)}
						<Descriptions
							column={1}
							size="small"
							bordered
						>
							<Descriptions.Item label="OAuth credential">
								<Space
									orientation="vertical"
									size={8}
								>
									{setup.oauthCredential === null
										? 'none'
										: setup.oauthCredential.kind === 'secret'
											? `secret, issued ${when(setup.oauthCredential.issuedAt)}`
											: `key${
													setup.oauthCredential.jwksUri
														? ` at ${setup.oauthCredential.jwksUri}`
														: setup.oauthCredential.keyCount !== undefined
															? ` (${setup.oauthCredential.keyCount} in the set)`
															: ''
												}, issued ${when(setup.oauthCredential.issuedAt)}`}
									{canEdit && (
										<Space wrap>
											<Button
												size="small"
												onClick={() => void issueSimple(setup, 'secret')}
											>
												{setup.oauthCredential
													? 'Replace with a secret…'
													: 'Issue secret'}
											</Button>
											<Button
												size="small"
												disabled={keyOpen}
												onClick={() => {
													keyForm.resetFields();
													setKeyOpen(true);
												}}
											>
												{setup.oauthCredential
													? 'Replace with a key…'
													: 'Issue key…'}
											</Button>
											{setup.oauthCredential && (
												<Button
													size="small"
													danger
													onClick={() => void revoke(setup, 'oauth')}
												>
													Revoke…
												</Button>
											)}
										</Space>
									)}
								</Space>
							</Descriptions.Item>
							<Descriptions.Item label="Static token">
								<Space
									orientation="vertical"
									size={8}
								>
									{setup.staticToken === null
										? 'none'
										: `issued ${when(setup.staticToken.issuedAt)}`}
									{canEdit && (
										<Space wrap>
											<Button
												size="small"
												onClick={() => void issueSimple(setup, 'static_token')}
											>
												{setup.staticToken
													? 'Replace static token…'
													: 'Issue static token'}
											</Button>
											{setup.staticToken && (
												<Button
													size="small"
													danger
													onClick={() => void revoke(setup, 'static_token')}
												>
													Revoke…
												</Button>
											)}
										</Space>
									)}
								</Space>
							</Descriptions.Item>
						</Descriptions>

						{/* Inline rather than a form dialog over the drawer, which would stack two layers. */}
						{canEdit && keyOpen && (
							<Card
								size="small"
								title={
									setup.oauthCredential
										? 'Replace with a key credential'
										: 'Issue a key credential'
								}
							>
								<Form<KeyValues>
									form={keyForm}
									layout="vertical"
									onFinish={onIssueKey}
									scrollToFirstError
									initialValues={{ source: 'jwks' }}
								>
									<Form.Item
										name="source"
										label="Public keys"
									>
										<Radio.Group
											options={[
												{ label: 'Paste a key set', value: 'jwks' },
												{ label: 'Fetch from a URL', value: 'jwksUri' }
											]}
										/>
									</Form.Item>
									{keySource === 'jwksUri' ? (
										<Form.Item
											name="jwksUri"
											label="JWKS URI"
											rules={[{ required: true, type: 'url' }]}
										>
											<Input
												autoComplete="off"
												placeholder="https://directory.example.com/jwks.json"
											/>
										</Form.Item>
									) : (
										<Form.Item
											name="jwksText"
											label="JWKS"
											tooltip="Public keys only. A private or symmetric key is refused."
											rules={[
												{ required: true },
												{
													validator: async (
														_rule,
														text: string | undefined
													) => {
														if (text?.trim()) parseJwks(text);
													}
												}
											]}
										>
											<Input.TextArea
												rows={6}
												spellCheck={false}
												placeholder='{"keys":[{"kty":"RSA","n":"…","e":"AQAB"}]}'
											/>
										</Form.Item>
									)}
									<Form.Item
										name="signingAlg"
										label="Signing algorithm"
										tooltip="Optional. The algorithm the directory signs its client assertions with."
									>
										<Input
											autoComplete="off"
											placeholder="RS256"
										/>
									</Form.Item>
									<Space>
										<Button
											type="primary"
											htmlType="submit"
											loading={saving}
										>
											{setup.oauthCredential ? 'Replace…' : 'Issue key'}
										</Button>
										<Button onClick={() => setKeyOpen(false)}>Cancel</Button>
									</Space>
								</Form>
							</Card>
						)}

						{/* Keyed on what it shows, so a save or a release resets the form to the server's state. */}
						<DeprovisioningGuard
							key={`${setup.id}:${JSON.stringify(setup.threshold ?? null)}:${setup.hold?.since ?? ''}`}
							connection={setup}
							canEdit={canEdit}
							onSave={(threshold) => saveThreshold(setup, threshold)}
							onRelease={() => startRelease(setup)}
						/>
					</Space>
				) : null}
			</Drawer>

			<ConfirmDestruction
				open={releasing !== null}
				title={
					releasing
						? `Release the hold on ${releasing.connection.displayName}?`
						: ''
				}
				consequences={[
					"The directory's retried deactivations and deletions go through, and those people lose access at once.",
					'The count starts again from zero.',
					'Check the directory for the mistake that tripped the guard first.'
				]}
				word="release"
				okText="Release hold"
				busy={saving}
				onCancel={endRelease}
				onConfirm={() => void release()}
			/>
		</div>
	);
}
