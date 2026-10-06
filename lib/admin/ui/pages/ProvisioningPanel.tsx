import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Descriptions,
	Drawer,
	Form,
	Input,
	Modal,
	Popconfirm,
	Radio,
	Select,
	Space,
	Switch,
	Table,
	Tag,
	Tooltip,
	Typography,
	message
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { FederationProvider } from '../../../federation/types.js';
import type {
	ConnectionView,
	ConnectionWarning
} from '../../../provisioning/service.js';
import { ConfirmDestruction } from '../ConfirmDestruction.js';

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

/* Which value the one-time modal is holding, so its warning names the thing being copied. */
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
	onChanged
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
}) {
	const bucketBase = `/admin/api/buckets/${encodeURIComponent(bucketId)}`;
	const base = `${bucketBase}/provisioning-connections`;
	const [rows, setRows] = useState<ConnectionView[]>([]);
	const [providers, setProviders] = useState<FederationProvider[]>([]);
	const [loading, setLoading] = useState(true);
	const [createOpen, setCreateOpen] = useState(false);
	const [saving, setSaving] = useState(false);
	const [setupId, setSetupId] = useState<string | null>(null);
	const [keyOpen, setKeyOpen] = useState(false);
	const [revealed, setRevealed] = useState<Revealed | null>(null);
	const [deleting, setDeleting] = useState<ConnectionView | null>(null);
	const [createForm] = Form.useForm<CreateValues>();
	const [keyForm] = Form.useForm<KeyValues>();
	const keySource = Form.useWatch('source', keyForm);

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchConnections = useCallback(async () => {
		try {
			const [connections, federation] = await Promise.all([
				fetch(base),
				fetch(`${bucketBase}/federation`)
			]);
			const list = connections.ok
				? ((await connections.json()) as ConnectionView[])
				: [];
			setRows(list);
			setProviders(
				federation.ok ? ((await federation.json()) as FederationProvider[]) : []
			);
			onConnections?.(list);
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

	/* One reporter for every mutation, so the server's reason is what an operator reads. */
	async function send<T>(
		path: string,
		method: string,
		body?: unknown
	): Promise<T | null> {
		const res = await fetch(path, {
			method,
			...(body
				? {
						headers: { 'content-type': 'application/json' },
						body: JSON.stringify(body)
					}
				: {})
		});
		const detail = (await res.json().catch(() => null)) as unknown;
		if (res.ok) return (detail ?? {}) as T;
		message.error(
			(detail as { message?: string } | null)?.message ??
				`request failed (${res.status})`
		);
		return null;
	}

	async function changed(event: 'created' | 'changed' | 'deleted') {
		await load();
		onChanged?.(event);
	}

	async function onCreate(values: CreateValues) {
		setSaving(true);
		try {
			const claim = values.correlationClaim?.trim();
			const created = await send<ConnectionView>(base, 'POST', {
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
			if (!created) return;
			setCreateOpen(false);
			createForm.resetFields();
			message.success(
				`connection created — ${created.providerId} now signs in existing accounts only`
			);
			await changed('created');
			setSetupId(created.id);
		} finally {
			setSaving(false);
		}
	}

	async function onToggle(row: ConnectionView, enabled: boolean) {
		if (
			await send(`${base}/${encodeURIComponent(row.id)}`, 'PATCH', { enabled })
		) {
			await changed('changed');
		}
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
		const issued = await send<{
			connection: ConnectionView;
			secret?: string;
			token?: string;
		}>(`${base}/${encodeURIComponent(row.id)}/credentials`, 'POST', body);
		if (!issued) return false;
		if (issued.secret) setRevealed({ noun: 'secret', value: issued.secret });
		if (issued.token) setRevealed({ noun: 'token', value: issued.token });
		if (body.kind === 'key') message.success('key credential issued');
		await changed('changed');
		return true;
	}

	async function onIssueKey(values: KeyValues) {
		if (!setup) return;
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
			await send(
				`${base}/${encodeURIComponent(row.id)}/credentials/${kind}`,
				'DELETE'
			)
		) {
			message.success(
				kind === 'oauth' ? 'OAuth credential revoked' : 'static token revoked'
			);
			await changed('changed');
		}
	}

	async function onDelete() {
		if (!deleting) return;
		setSaving(true);
		try {
			if (await send(`${base}/${encodeURIComponent(deleting.id)}`, 'DELETE')) {
				setDeleting(null);
				if (setupId === deleting.id) setSetupId(null);
				await changed('deleted');
			}
		} finally {
			setSaving(false);
		}
	}

	/* A provider holds at most one connection, so the select never offers one the server would refuse. */
	const bound = new Set(rows.map((row) => row.providerId));
	const providerOptions = providers
		.filter((p) => !bound.has(p.id))
		.map((p) => ({
			label: `${p.displayName} (${p.id})`,
			value: p.id
		}));

	/*
	 * The OAuth credential is one slot, key or secret: issuing either replaces whichever is there, and every
	 * token the old one obtained is revoked with it. Said before the click, because the directory that holds
	 * the old one stops working the moment this is confirmed.
	 */
	const replacesOauth = (row: ConnectionView) =>
		row.oauthCredential
			? `This replaces the current ${row.oauthCredential.kind} credential and revokes every token it obtained. The directory stops working until it is given the new one.`
			: 'The directory will authenticate with this credential.';

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
				<Tooltip
					title={
						providerOptions.length === 0
							? 'Every identity provider on this bucket already has a connection — add a provider first'
							: undefined
					}
				>
					<Button
						icon={<PlusOutlined />}
						disabled={providerOptions.length === 0}
						onClick={() => {
							createForm.resetFields();
							setCreateOpen(true);
						}}
					>
						New connection
					</Button>
				</Tooltip>
			</Space>

			<Typography.Paragraph type="secondary">
				A connection lets a directory create, update and remove this bucket's
				users. Each one is bound to an identity provider above, which then signs
				in existing accounts only, so a person is never created twice.
			</Typography.Paragraph>

			<Table<ConnectionView>
				rowKey="id"
				loading={loading}
				dataSource={rows}
				pagination={false}
				columns={[
					{ title: 'Name', dataIndex: 'displayName' },
					{ title: 'Provider', dataIndex: 'providerId' },
					{
						title: 'Enabled',
						dataIndex: 'enabled',
						render: (enabled: boolean, row) => (
							<Switch
								size="small"
								checked={enabled}
								aria-label={`${row.displayName} enabled`}
								onChange={(next) => void onToggle(row, next)}
							/>
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
					{
						title: '',
						render: (_, row) => (
							<Space>
								<Button
									size="small"
									onClick={() => setSetupId(row.id)}
								>
									Setup
								</Button>
								{/* Refused by the server while it manages anyone, because people must never
								    be removed or released as a side effect of deleting configuration. */}
								<Tooltip
									title={
										row.managedUsers > 0
											? `Manages ${row.managedUsers} user${row.managedUsers === 1 ? '' : 's'} — disable it instead, or remove them through the directory first`
											: undefined
									}
								>
									<Button
										size="small"
										danger
										disabled={row.managedUsers > 0}
										onClick={() => setDeleting(row)}
									>
										Delete
									</Button>
								</Tooltip>
							</Space>
						)
					}
				]}
			/>

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
				width={640}
				open={setup !== null}
				onClose={() => setSetupId(null)}
				title={setup ? `Set up ${setup.displayName}` : ''}
			>
				{setup ? (
					<Space
						direction="vertical"
						size="middle"
						style={{ width: '100%' }}
					>
						{setup.warnings.length > 0 && (
							<Alert
								type="warning"
								showIcon
								message="The directory's requests will be refused until this is fixed"
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
						<Descriptions
							column={1}
							size="small"
							bordered
						>
							<Descriptions.Item label="OAuth credential">
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
							</Descriptions.Item>
							<Descriptions.Item label="Static token">
								{setup.staticToken === null
									? 'none'
									: `issued ${when(setup.staticToken.issuedAt)}`}
							</Descriptions.Item>
						</Descriptions>
						<Space wrap>
							<Popconfirm
								title="Issue a key credential?"
								description={replacesOauth(setup)}
								okText="Continue"
								onConfirm={() => {
									keyForm.resetFields();
									setKeyOpen(true);
								}}
							>
								<Button>Issue key credential</Button>
							</Popconfirm>
							<Popconfirm
								title="Issue a secret?"
								description={replacesOauth(setup)}
								okText="Issue"
								onConfirm={() => issue(setup, { kind: 'secret' })}
							>
								<Button>Issue secret</Button>
							</Popconfirm>
							<Popconfirm
								title="Issue a static token?"
								description={
									setup.staticToken
										? 'This replaces the current static token, which stops working immediately. The directory stops working until it is given the new one.'
										: 'The directory will send this token in the Authorization header.'
								}
								okText="Issue"
								onConfirm={() => issue(setup, { kind: 'static_token' })}
							>
								<Button>Issue static token</Button>
							</Popconfirm>
							<Popconfirm
								title="Revoke the OAuth credential?"
								description="Every token it obtained is revoked and the directory can no longer authenticate with it."
								okText="Revoke"
								onConfirm={() => revoke(setup, 'oauth')}
								disabled={setup.oauthCredential === null}
							>
								<Button
									danger
									disabled={setup.oauthCredential === null}
								>
									Revoke OAuth credential
								</Button>
							</Popconfirm>
							<Popconfirm
								title="Revoke the static token?"
								description="The directory can no longer authenticate with it."
								okText="Revoke"
								onConfirm={() => revoke(setup, 'static_token')}
								disabled={setup.staticToken === null}
							>
								<Button
									danger
									disabled={setup.staticToken === null}
								>
									Revoke static token
								</Button>
							</Popconfirm>
						</Space>
					</Space>
				) : null}
			</Drawer>

			<Modal
				title="Issue key credential"
				open={keyOpen}
				onCancel={() => setKeyOpen(false)}
				onOk={() => keyForm.submit()}
				confirmLoading={saving}
				destroyOnHidden
			>
				<Form<KeyValues>
					form={keyForm}
					layout="vertical"
					onFinish={onIssueKey}
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
									validator: async (_rule, text: string | undefined) => {
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
				</Form>
			</Modal>

			<Modal
				title={revealed?.noun === 'token' ? 'Static token' : 'Client secret'}
				open={revealed !== null}
				onOk={() => setRevealed(null)}
				onCancel={() => setRevealed(null)}
				cancelButtonProps={{ style: { display: 'none' } }}
			>
				<Typography.Paragraph type="warning">
					Copy this {revealed?.noun} now — it will not be shown again.
				</Typography.Paragraph>
				<Typography.Paragraph
					copyable
					code
				>
					{revealed?.value}
				</Typography.Paragraph>
			</Modal>

			<ConfirmDestruction
				open={deleting !== null}
				title={deleting ? `Delete ${deleting.displayName}?` : ''}
				consequences={[
					'The directory can no longer provision this bucket, and every token it holds is revoked.',
					'Its identity provider stays on this bucket, still limited to existing accounts.'
				]}
				busy={saving}
				onCancel={() => setDeleting(null)}
				onConfirm={() => void onDelete()}
			/>
		</div>
	);
}
