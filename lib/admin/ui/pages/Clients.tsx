import { useCallback, useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	Select,
	Space,
	Typography,
	Popconfirm,
	Switch,
	Tag,
	Collapse,
	message
} from 'antd';
import { PlusOutlined, ArrowLeftOutlined } from '@ant-design/icons';
import type { Project } from '../../../adapters/types.js';

const GRANT_OPTIONS = [
	{ label: 'authorization_code', value: 'authorization_code' },
	{ label: 'refresh_token', value: 'refresh_token' },
	{ label: 'client_credentials', value: 'client_credentials' },
	{
		label: 'device_code',
		value: 'urn:ietf:params:oauth:grant-type:device_code'
	},
	{ label: 'ciba', value: 'urn:openid:params:grant-type:ciba' }
];
const AUTH_OPTIONS = [
	{ label: 'none (public / PKCE)', value: 'none' },
	{ label: 'client_secret_basic', value: 'client_secret_basic' },
	{ label: 'client_secret_post', value: 'client_secret_post' },
	{ label: 'client_secret_jwt', value: 'client_secret_jwt' },
	{ label: 'private_key_jwt (key set below)', value: 'private_key_jwt' }
];

/*
 * The key and request-protection attributes, as text fields and switches. Algorithms are free text:
 * the set a deployment supports is the server's to check, and a picker here would be a second copy
 * of it. An emptied text field on an edit removes the attribute.
 */
const KEY_TEXT_FIELDS = [
	['jwksUri', 'Key set URL (jwks_uri)', 'https://app.example.com/jwks'],
	['tokenEndpointAuthSigningAlg', 'Client assertion signing alg', 'PS256'],
	['idTokenSignedResponseAlg', 'ID Token signing alg', 'RS256'],
	['authorizationSignedResponseAlg', 'JARM signing alg', 'PS256'],
	['requestObjectSigningAlg', 'Request Object signing alg', 'PS256'],
	[
		'backchannelLogoutUri',
		'Back-channel logout URI',
		'https://app.example.com/logout'
	],
	[
		'sectorIdentifierUri',
		'Sector identifier URI (pairwise)',
		'https://app.example.com/sector.json'
	]
] as const;
const KEY_SWITCHES = [
	['requirePushedAuthorizationRequests', 'Require pushed authorization (PAR)'],
	['dpopBoundAccessTokens', 'Require DPoP-bound access tokens'],
	['requireSignedRequestObject', 'Require signed Request Objects'],
	['backchannelLogoutSessionRequired', 'Send sid in logout tokens']
] as const;
type KeyTextField = (typeof KEY_TEXT_FIELDS)[number][0];
type KeySwitch = (typeof KEY_SWITCHES)[number][0];
type KeyAttributes = { [K in KeyTextField]?: string } & {
	[K in KeySwitch]?: boolean;
} & { subjectType?: 'public' | 'pairwise'; jwks?: unknown };

function parseJwks(text: string | undefined): unknown {
	const trimmed = text?.trim();
	if (!trimmed) return undefined;
	const value: unknown = JSON.parse(trimmed);
	if (typeof value !== 'object' || value === null || !('keys' in value)) {
		throw new TypeError('a key set is a JSON object with a "keys" array');
	}
	return value;
}
const CIBA_GRANT_TYPE = 'urn:openid:params:grant-type:ciba';
// Mirrors the request schema's union, which is the server's real answer on what it will accept.
const CIBA_DELIVERY_MODE_OPTIONS = [
	{ label: 'poll', value: 'poll' },
	{ label: 'ping', value: 'ping' }
];

interface ClientView {
	clientId: string;
	clientName?: string;
	applicationType: string;
	grantTypes: string[];
	tokenEndpointAuthMethod: string;
	redirectUris: string[];
	scope?: string;
	requireConsent: boolean;
	backchannelTokenDeliveryMode?: 'poll' | 'ping';
	backchannelClientNotificationEndpoint?: string;
	authorizationDetailsTypes?: string[];
	registeredDynamically?: boolean;
}
type ClientRow = ClientView & KeyAttributes;
interface FormValues extends Omit<KeyAttributes, 'jwks'> {
	jwksText?: string;
	clientName?: string;
	applicationType: 'web' | 'native';
	grantTypes: string[];
	tokenEndpointAuthMethod: string;
	redirectUris?: string;
	scope?: string;
	requireConsent: boolean;
	backchannelTokenDeliveryMode?: 'poll' | 'ping';
	backchannelClientNotificationEndpoint?: string;
	authorizationDetailsTypes?: string[];
}

const DEFAULT_VALUES: FormValues = {
	applicationType: 'web',
	grantTypes: ['authorization_code'],
	tokenEndpointAuthMethod: 'none',
	requireConsent: true
};

export function Clients({
	project,
	onBack
}: {
	project: Project;
	onBack: () => void;
}) {
	const base = `/admin/api/projects/${project._id}/clients`;
	const [rows, setRows] = useState<ClientRow[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [mode, setMode] = useState<'create' | 'edit'>('create');
	const [editingClientId, setEditingClientId] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);
	const [secret, setSecret] = useState<string | null>(null);
	const [form] = Form.useForm<FormValues>();

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchClients = useCallback(async () => {
		try {
			const res = await fetch(base);
			if (res.ok) setRows((await res.json()) as ClientRow[]);
		} finally {
			setLoading(false);
		}
	}, [base]);
	function load() {
		setLoading(true);
		return fetchClients();
	}
	useEffect(() => {
		void fetchClients();
	}, [fetchClients]);

	function openCreateModal() {
		setMode('create');
		setEditingClientId(null);
		form.resetFields();
		setOpen(true);
	}

	function openEditModal(row: ClientRow) {
		setMode('edit');
		setEditingClientId(row.clientId);
		form.setFieldsValue({
			clientName: row.clientName,
			applicationType: row.applicationType as 'web' | 'native',
			grantTypes: row.grantTypes,
			tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
			redirectUris: row.redirectUris.join('\n'),
			scope: row.scope,
			requireConsent: row.requireConsent,
			authorizationDetailsTypes: row.authorizationDetailsTypes,
			backchannelTokenDeliveryMode: row.backchannelTokenDeliveryMode,
			backchannelClientNotificationEndpoint:
				row.backchannelClientNotificationEndpoint,
			jwksText: row.jwks ? JSON.stringify(row.jwks, null, 2) : '',
			subjectType: row.subjectType,
			...Object.fromEntries(
				KEY_TEXT_FIELDS.map(([name]) => [name, row[name] ?? ''])
			),
			...Object.fromEntries(
				KEY_SWITCHES.map(([name]) => [name, row[name] ?? false])
			)
		});
		setOpen(true);
	}

	/*
	 * On create an attribute is sent only when set. On an edit every one is sent, an emptied text
	 * field as null — which removes it — so what the form shows is what the client then holds.
	 */
	function keyAttributes(values: FormValues, editing: boolean) {
		const body: Record<string, unknown> = {};
		const jwks = parseJwks(values.jwksText);
		if (jwks !== undefined || editing) body.jwks = jwks ?? null;
		for (const [name] of KEY_TEXT_FIELDS) {
			const value = values[name]?.trim();
			if (value || editing) body[name] = value || null;
		}
		for (const [name] of KEY_SWITCHES) {
			if (values[name] || editing) body[name] = Boolean(values[name]);
		}
		if (values.subjectType) body.subjectType = values.subjectType;
		return body;
	}

	function buildBody(values: FormValues, editing = false) {
		return {
			...keyAttributes(values, editing),
			clientName: values.clientName,
			applicationType: values.applicationType,
			grantTypes: values.grantTypes,
			tokenEndpointAuthMethod: values.tokenEndpointAuthMethod,
			redirectUris: (values.redirectUris ?? '')
				.split('\n')
				.map((s) => s.trim())
				.filter(Boolean),
			scope: values.scope,
			requireConsent: values.requireConsent,
			...(values.authorizationDetailsTypes?.length
				? { authorizationDetailsTypes: values.authorizationDetailsTypes }
				: {}),
			...(values.backchannelTokenDeliveryMode
				? {
						backchannelTokenDeliveryMode: values.backchannelTokenDeliveryMode
					}
				: {}),
			...(values.backchannelClientNotificationEndpoint
				? {
						backchannelClientNotificationEndpoint:
							values.backchannelClientNotificationEndpoint
					}
				: {})
		};
	}

	async function onCreate(values: FormValues) {
		const res = await fetch(base, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(buildBody(values))
		});
		const body = (await res.json().catch(() => null)) as {
			message?: string;
			secret?: string;
		} | null;
		if (!res.ok) {
			message.error(body?.message || 'failed to create client');
			return;
		}
		setOpen(false);
		form.resetFields();
		if (body?.secret) setSecret(body.secret);
		await load();
	}

	async function onUpdate(clientId: string, values: FormValues) {
		const res = await fetch(`${base}/${encodeURIComponent(clientId)}`, {
			method: 'PATCH',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(buildBody(values, true))
		});
		const body = (await res.json().catch(() => null)) as {
			message?: string;
		} | null;
		if (!res.ok) {
			message.error(body?.message || 'failed to update client');
			return;
		}
		setOpen(false);
		form.resetFields();
		await load();
	}

	async function onSubmit(values: FormValues) {
		setSaving(true);
		try {
			if (mode === 'edit' && editingClientId) {
				await onUpdate(editingClientId, values);
			} else {
				await onCreate(values);
			}
		} finally {
			setSaving(false);
		}
	}

	async function onDelete(clientId: string) {
		const res = await fetch(`${base}/${encodeURIComponent(clientId)}`, {
			method: 'DELETE'
		});
		if (!res.ok) {
			message.error('failed to delete client');
			return;
		}
		await load();
	}

	async function onRotate(clientId: string) {
		const res = await fetch(`${base}/${encodeURIComponent(clientId)}/secret`, {
			method: 'POST'
		});
		const body = (await res.json().catch(() => null)) as {
			secret?: string;
		} | null;
		if (!res.ok || !body?.secret) {
			message.error('failed to rotate secret');
			return;
		}
		setSecret(body.secret);
	}

	return (
		<>
			<Space
				style={{
					marginBottom: 16,
					justifyContent: 'space-between',
					width: '100%'
				}}
			>
				<Button
					icon={<ArrowLeftOutlined />}
					onClick={onBack}
				>
					Projects
				</Button>
				<Typography.Title
					level={4}
					style={{ margin: 0 }}
				>
					{project.name} — clients
				</Typography.Title>
				<Button
					type="primary"
					icon={<PlusOutlined />}
					onClick={openCreateModal}
				>
					New client
				</Button>
			</Space>
			<Table<ClientView>
				rowKey="clientId"
				loading={loading}
				dataSource={rows}
				columns={[
					{
						title: 'Name',
						dataIndex: 'clientName',
						/*
						 * A client the server created on its own request is marked here rather than left to be
						 * inferred from the shape of its id. It cannot be inferred: a deployment's `idFactory`
						 * may issue any id, including a URL, so "looks generated" is not a distinction. What an
						 * operator needs to know is who vouched for the client — them, or nobody.
						 */
						render: (clientName: string | undefined, row: ClientView) => (
							<Space size={4}>
								<span>{clientName || '—'}</span>
								{row.registeredDynamically ? <Tag>self-registered</Tag> : null}
							</Space>
						)
					},
					{ title: 'Client ID', dataIndex: 'clientId' },
					{ title: 'Type', dataIndex: 'applicationType' },
					{ title: 'Auth', dataIndex: 'tokenEndpointAuthMethod' },
					{
						title: 'Grants',
						dataIndex: 'grantTypes',
						render: (g: string[]) => g.join(', ')
					},
					{
						title: 'Actions',
						render: (_: unknown, row: ClientView) => (
							<Space>
								<Button
									size="small"
									onClick={() => openEditModal(row)}
								>
									Edit
								</Button>
								{row.tokenEndpointAuthMethod !== 'none' && (
									<Button
										size="small"
										onClick={() => onRotate(row.clientId)}
									>
										Rotate secret
									</Button>
								)}
								{/* States the consequence rather than asking for confirmation of an unstated one:
								    deleting a client destroys every credential it ever issued, and the invisible
								    half of that is what an operator cannot otherwise see. */}
								<Popconfirm
									title="Delete this client?"
									description="Its access, refresh and machine-to-machine tokens, pending codes, consent records and its own registration credential are all destroyed immediately."
									okText="Delete and revoke"
									onConfirm={() => onDelete(row.clientId)}
								>
									<Button
										size="small"
										danger
									>
										Delete
									</Button>
								</Popconfirm>
							</Space>
						)
					}
				]}
			/>
			<Modal
				title={mode === 'create' ? 'New client' : 'Edit client'}
				open={open}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				confirmLoading={saving}
				destroyOnHidden
			>
				<Form<FormValues>
					form={form}
					layout="vertical"
					onFinish={onSubmit}
					initialValues={DEFAULT_VALUES}
				>
					<Form.Item
						name="clientName"
						label="Name"
					>
						<Input />
					</Form.Item>
					<Form.Item
						name="applicationType"
						label="Application type"
					>
						<Select
							options={[
								{ label: 'web', value: 'web' },
								{ label: 'native', value: 'native' }
							]}
						/>
					</Form.Item>
					<Form.Item
						name="grantTypes"
						label="Grant types"
						rules={[{ required: true }]}
					>
						<Select
							mode="multiple"
							options={GRANT_OPTIONS}
						/>
					</Form.Item>
					<Form.Item
						name="tokenEndpointAuthMethod"
						label="Token endpoint auth"
					>
						<Select options={AUTH_OPTIONS} />
					</Form.Item>
					<Form.Item
						name="redirectUris"
						label="Redirect URIs (one per line)"
					>
						<Input.TextArea
							rows={3}
							placeholder="https://app.example.com/cb"
						/>
					</Form.Item>
					<Form.Item
						name="scope"
						label="Scope"
					>
						<Input placeholder="openid profile email" />
					</Form.Item>
					<Form.Item
						name="requireConsent"
						label="Require consent"
						valuePropName="checked"
					>
						<Switch />
					</Form.Item>
					{/*
					 * Free-form tags rather than a picker over the configured types: the server validates
					 * each value against them and reports its own message, and gating this field on the
					 * feature flag here would restate a server rule in a second place.
					 */}
					<Form.Item
						name="authorizationDetailsTypes"
						label="Authorization details types (RAR)"
					>
						<Select
							mode="tags"
							placeholder="https://scheme.example/payment"
						/>
					</Form.Item>
					<Form.Item<FormValues>
						shouldUpdate={(prev, cur) => prev.grantTypes !== cur.grantTypes}
					>
						{() => {
							const grantTypes =
								(form.getFieldValue('grantTypes') as string[] | undefined) ??
								[];
							if (!grantTypes.includes(CIBA_GRANT_TYPE)) return null;
							return (
								<>
									<Form.Item
										name="backchannelTokenDeliveryMode"
										label="Backchannel token delivery mode"
										rules={[{ required: true }]}
									>
										<Select options={CIBA_DELIVERY_MODE_OPTIONS} />
									</Form.Item>
									<Form.Item
										name="backchannelClientNotificationEndpoint"
										label="Backchannel client notification endpoint"
									>
										<Input placeholder="https://app.example.com/ciba/notify" />
									</Form.Item>
								</>
							);
						}}
					</Form.Item>
					<Collapse
						ghost
						items={[
							{
								key: 'keys',
								label: 'Key & request security',
								forceRender: true,
								children: (
									<>
										<Form.Item
											name="jwksText"
											label="Key set (jwks)"
											tooltip="The client's public keys, for private_key_jwt and signed Request Objects. Public material only — a private key is refused. Use this or the key set URL, not both."
											rules={[
												{
													validator: async (
														_rule,
														text: string | undefined
													) => {
														parseJwks(text);
													}
												}
											]}
										>
											<Input.TextArea
												rows={4}
												spellCheck={false}
												placeholder='{"keys":[{"kty":"EC","crv":"P-256","x":"…","y":"…"}]}'
											/>
										</Form.Item>
										{KEY_TEXT_FIELDS.map(([name, label, placeholder]) => (
											<Form.Item
												key={name}
												name={name}
												label={label}
											>
												<Input placeholder={placeholder} />
											</Form.Item>
										))}
										<Form.Item
											name="subjectType"
											label="Subject type"
										>
											<Select
												allowClear
												options={[
													{ label: 'public', value: 'public' },
													{ label: 'pairwise', value: 'pairwise' }
												]}
											/>
										</Form.Item>
										{KEY_SWITCHES.map(([name, label]) => (
											<Form.Item
												key={name}
												name={name}
												label={label}
												valuePropName="checked"
											>
												<Switch />
											</Form.Item>
										))}
									</>
								)
							}
						]}
					/>
				</Form>
			</Modal>
			<Modal
				title="Client secret"
				open={secret !== null}
				onOk={() => setSecret(null)}
				onCancel={() => setSecret(null)}
				cancelButtonProps={{ style: { display: 'none' } }}
			>
				<Typography.Paragraph type="warning">
					Copy this secret now — it will not be shown again.
				</Typography.Paragraph>
				<Typography.Paragraph
					copyable
					code
				>
					{secret}
				</Typography.Paragraph>
			</Modal>
		</>
	);
}
