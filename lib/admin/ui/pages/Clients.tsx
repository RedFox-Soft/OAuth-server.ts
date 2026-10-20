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
	Typography,
	Switch,
	Tag,
	Collapse,
	Tooltip,
	Upload,
	ColorPicker
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { AreaToolbar } from '../frame/AreaToolbar.js';
import { RowActions, type RowAction } from '../frame/RowActions.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import { SecretReveal } from '../frame/SecretReveal.js';
import { atLimit, type PlanView } from '../planText.js';
import {
	LOGO_MAX_BYTES,
	LOGO_SIZE_MESSAGE
} from '../../../consts/client_logo.js';
import { grantRefusedToPublicClient } from '../../../consts/confidential_grants.js';
import { paintedAccent } from '../../../html/theme/accent.js';

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
	partialConsent?: boolean;
	backchannelTokenDeliveryMode?: 'poll' | 'ping';
	backchannelClientNotificationEndpoint?: string;
	authorizationDetailsTypes?: string[];
	registeredDynamically?: boolean;
	hasLogo?: boolean;
	primaryColor?: string;
	policyUri?: string;
	tosUri?: string;
	corsOrigins?: string[];
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
	partialConsent?: boolean;
	backchannelTokenDeliveryMode?: 'poll' | 'ping';
	backchannelClientNotificationEndpoint?: string;
	authorizationDetailsTypes?: string[];
	logo?: string | null;
	primaryColor?: string | null;
	policyUri?: string;
	tosUri?: string;
	corsOrigins?: string[];
}

/*
 * The application's browser origins (specs/099). Validation is deliberately left to the server: it owns
 * the one rule shared with the request path, and its refusal names the offending value and the canonical
 * form it should have been. An application in the same bucket is usually the same product, so its list
 * can be copied in one step instead of retyped.
 */
function OriginsField({
	value,
	onChange,
	siblings
}: {
	value?: string[];
	onChange?: (value: string[]) => void;
	siblings: { label: string; origins: string[] }[];
}) {
	const origins = value ?? [];
	const [draft, setDraft] = useState('');
	function add() {
		const next = draft.trim();
		setDraft('');
		if (next && !origins.includes(next)) onChange?.([...origins, next]);
	}
	return (
		<Space
			orientation="vertical"
			size={8}
			style={{ width: '100%' }}
		>
			<Space wrap>
				{origins.length === 0 && (
					<Typography.Text type="secondary">No origins</Typography.Text>
				)}
				{origins.map((origin) => (
					<Tag
						key={origin}
						closable
						onClose={() => onChange?.(origins.filter((o) => o !== origin))}
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
					onPressEnter={(e) => {
						e.preventDefault();
						add();
					}}
				/>
				<Button onClick={add}>Add</Button>
			</Space.Compact>
			{siblings.length > 0 && (
				<Select<number>
					placeholder="Copy from another application of this project"
					style={{ width: '100%' }}
					value={null}
					options={siblings.map((sibling, index) => ({
						label: `${sibling.label} (${sibling.origins.length})`,
						value: index
					}))}
					onChange={(index) => {
						const picked = siblings.at(index);
						if (picked) {
							onChange?.([...new Set([...origins, ...picked.origins])]);
						}
					}}
				/>
			)}
		</Space>
	);
}

/*
 * The client's logo as the consent page will show it, read into a `data:` URL in the browser: the admin
 * API takes the image in the body, so no upload route exists. The size is checked here only to say so
 * sooner; what the bytes are is the server's decision.
 */
function LogoField({
	value,
	onChange
}: {
	value?: string | null;
	onChange?: (value: string | null) => void;
}) {
	const [tooLarge, setTooLarge] = useState(false);
	return (
		<Space
			orientation="vertical"
			size={4}
		>
			<Space align="center">
				{value ? (
					<img
						src={value}
						alt="Current logo"
						width={40}
						height={40}
						style={{
							display: 'block',
							objectFit: 'contain',
							padding: 3,
							boxSizing: 'border-box',
							background: '#f6f7f9',
							border: '1px solid #e6e8eb',
							borderRadius: 8
						}}
					/>
				) : (
					<Typography.Text type="secondary">No logo</Typography.Text>
				)}
				<Upload
					accept="image/png,image/jpeg,image/webp"
					showUploadList={false}
					beforeUpload={(file) => {
						if (file.size > LOGO_MAX_BYTES) {
							setTooLarge(true);
							return false;
						}
						const reader = new FileReader();
						reader.onload = () => {
							if (typeof reader.result !== 'string') return;
							setTooLarge(false);
							onChange?.(reader.result);
						};
						reader.readAsDataURL(file);
						return false;
					}}
				>
					<Button>{value ? 'Replace' : 'Upload'}</Button>
				</Upload>
				{value ? (
					<Button onClick={() => onChange?.(null)}>Remove</Button>
				) : null}
			</Space>
			{tooLarge ? (
				<Typography.Text type="danger">{LOGO_SIZE_MESSAGE}</Typography.Text>
			) : null}
		</Space>
	);
}

/*
 * The application's colour, and what its sign-in pages will make of it: a primary button on a light page and on a
 * dark one, painted by the very code the pages use (lib/html/theme/accent.ts), so the preview is the page.
 */
function PrimaryColorField({
	value,
	onChange
}: {
	value?: string | null;
	onChange?: (value: string | null) => void;
}) {
	const accent = value ? paintedAccent(value) : undefined;
	const tile = (background: string, fill: string, scheme: string) => (
		<span
			style={{
				display: 'inline-flex',
				alignItems: 'center',
				padding: 8,
				borderRadius: 8,
				background,
				border: '1px solid #e6e8eb'
			}}
		>
			<span
				role="img"
				aria-label={`Primary button on a ${scheme} page, ${fill}`}
				style={{
					padding: '4px 12px',
					borderRadius: 6,
					background: fill,
					color: '#ffffff'
				}}
			>
				Continue
			</span>
		</span>
	);
	return (
		<Space
			orientation="vertical"
			size={4}
		>
			<Space align="center">
				<ColorPicker
					value={value ?? undefined}
					format="hex"
					disabledAlpha
					disabledFormat
					showText={() => value ?? 'Server default'}
					onChangeComplete={(color) => onChange?.(color.toHexString())}
				/>
				{value ? (
					<Button onClick={() => onChange?.(null)}>Remove</Button>
				) : null}
			</Space>
			{accent ? (
				<Space align="center">
					{tile('#ffffff', accent.light.primary, 'light')}
					{tile('#141414', accent.dark.primary, 'dark')}
				</Space>
			) : null}
			{accent?.adjusted ? (
				<Typography.Text type="secondary">
					Adjusted for legibility — people will see the shades shown.
				</Typography.Text>
			) : null}
		</Space>
	);
}

const DEFAULT_VALUES: FormValues = {
	applicationType: 'web',
	grantTypes: ['authorization_code'],
	tokenEndpointAuthMethod: 'none',
	requireConsent: true
};

/*
 * A bucket's applications (specs/099). `writable` is the bucket's stated `edit` right; a self-registered
 * application is listed and readable but managed through its own registration access token.
 */
export function Clients({
	bucketId,
	writable,
	plan,
	onChanged
}: {
	bucketId: string;
	writable: boolean;
	/* The plan the caller is held to (specs/102); null when nothing limits them. */
	plan?: PlanView | null;
	/* An application was added or deleted: the project's counts, and so its plan's use, changed. */
	onChanged?: () => void;
}) {
	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}/clients`;
	const [rows, setRows] = useState<ClientRow[]>([]);
	const [loading, setLoading] = useState(true);
	const [loadFailed, setLoadFailed] = useState<string | null>(null);
	const [open, setOpen] = useState(false);
	const [mode, setMode] = useState<'create' | 'edit'>('create');
	const [editingClientId, setEditingClientId] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);
	const [secret, setSecret] = useState<string | null>(null);
	const [secretStored, setSecretStored] = useState(false);
	// The logo the client had when the form opened: an edit sends `logo` only when it changed.
	const [storedLogo, setStoredLogo] = useState<string | null>(null);
	const [form] = Form.useForm<FormValues>();
	const feedback = useFeedback();
	const confirm = useConfirm();

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchClients = useCallback(
		() =>
			request<ClientRow[]>('GET', base).then((result) => {
				if (result.ok) {
					setRows(result.data);
					setLoadFailed(null);
				} else {
					setLoadFailed(result.error.message);
				}
				setLoading(false);
			}),
		[base]
	);
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
		setStoredLogo(null);
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
			partialConsent: row.partialConsent ?? false,
			authorizationDetailsTypes: row.authorizationDetailsTypes,
			backchannelTokenDeliveryMode: row.backchannelTokenDeliveryMode,
			backchannelClientNotificationEndpoint:
				row.backchannelClientNotificationEndpoint,
			policyUri: row.policyUri ?? '',
			tosUri: row.tosUri ?? '',
			corsOrigins: row.corsOrigins ?? [],
			logo: null,
			primaryColor: row.primaryColor ?? null,
			jwksText: row.jwks ? JSON.stringify(row.jwks, null, 2) : '',
			subjectType: row.subjectType,
			...Object.fromEntries(
				KEY_TEXT_FIELDS.map(([name]) => [name, row[name] ?? ''])
			),
			...Object.fromEntries(
				KEY_SWITCHES.map(([name]) => [name, row[name] ?? false])
			)
		});
		setStoredLogo(null);
		setOpen(true);
		// The list carries whether there is a logo, never the image, so the image is read on its own.
		if (row.hasLogo) {
			void request<{ logo?: string }>(
				'GET',
				`${base}/${encodeURIComponent(row.clientId)}`
			).then((result) => {
				if (!result.ok || !result.data.logo) return;
				setStoredLogo(result.data.logo);
				form.setFieldValue('logo', result.data.logo);
			});
		}
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

	function presentation(values: FormValues, editing: boolean) {
		const body: Record<string, unknown> = {};
		for (const name of ['policyUri', 'tosUri'] as const) {
			const value = values[name]?.trim();
			if (value || editing) body[name] = value || null;
		}
		const logo = values.logo ?? null;
		if (editing ? logo !== storedLogo : logo) body.logo = logo;
		// Sent on an edit only when changed, so saving an unrelated field never writes the colour back.
		const colour = values.primaryColor ?? null;
		const storedColour = editing
			? (rows.find((row) => row.clientId === editingClientId)?.primaryColor ??
				null)
			: null;
		if (editing ? colour !== storedColour : colour) body.primaryColor = colour;
		return body;
	}

	function buildBody(values: FormValues, editing = false) {
		return {
			...keyAttributes(values, editing),
			...presentation(values, editing),
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
			partialConsent: Boolean(values.partialConsent),
			corsOrigins: values.corsOrigins ?? [],
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
		const result = await request<{ secret?: string }>(
			'POST',
			base,
			buildBody(values)
		);
		if (!result.ok) {
			feedback.failed(result, form);
			return;
		}
		feedback.done('Client created.');
		setOpen(false);
		form.resetFields();
		if (result.data.secret) setSecret(result.data.secret);
		onChanged?.();
		await load();
	}

	async function onUpdate(clientId: string, values: FormValues) {
		const result = await request(
			'PATCH',
			`${base}/${encodeURIComponent(clientId)}`,
			buildBody(values, true)
		);
		if (!result.ok) {
			feedback.failed(result, form);
			return;
		}
		feedback.done('Client saved.');
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

	/*
	 * States the consequence rather than asking for confirmation of an unstated one: deleting a client
	 * destroys every credential it ever issued, and the invisible half of that is what an operator
	 * cannot otherwise see.
	 */
	async function onDelete(row: ClientView) {
		const agreed = await confirm('client.delete', {
			target: row.clientName || row.clientId,
			consequences: [
				'Its access, refresh and machine-to-machine tokens stop working immediately.',
				'Its pending codes and consent records are destroyed.',
				'Its own registration credential is destroyed.'
			]
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(row.clientId)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done('Client deleted.');
		onChanged?.();
		await load();
	}

	async function onRotate(row: ClientView) {
		const agreed = await confirm('client.secret.rotate', {
			target: row.clientName || row.clientId,
			consequences: [
				'The current secret stops working immediately.',
				'The application fails to authenticate until it is given the new secret.'
			]
		});
		if (!agreed) return;
		const result = await request<{ secret?: string }>(
			'POST',
			`${base}/${encodeURIComponent(row.clientId)}/secret`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done('Client secret rotated.');
		if (result.data.secret) setSecret(result.data.secret);
	}

	function actionsFor(row: ClientRow): RowAction[] {
		const items: RowAction[] = [
			{
				key: 'edit',
				label: 'Edit…',
				group: 'edit',
				onClick: () => openEditModal(row)
			}
		];
		if (row.tokenEndpointAuthMethod !== 'none') {
			items.push({
				key: 'rotate',
				label: 'Rotate secret',
				group: 'state',
				onClick: () => void onRotate(row)
			});
		}
		items.push({
			key: 'delete',
			label: 'Delete',
			group: 'danger',
			onClick: () => void onDelete(row)
		});
		return items;
	}

	const full = atLimit(plan, 'applications');
	const newClient = (
		<Tooltip title={full ?? undefined}>
			<Button
				type="primary"
				icon={<PlusOutlined />}
				disabled={full !== null}
				onClick={openCreateModal}
			>
				New application
			</Button>
		</Tooltip>
	);

	return (
		<>
			{writable ? (
				<AreaToolbar create={newClient} />
			) : (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title="These applications are read-only to you"
					description="Changing a project's applications takes membership of the team that owns it."
				/>
			)}
			{loadFailed !== null ? (
				<LoadFailed
					reason={loadFailed}
					onRetry={() => void load()}
				/>
			) : (
				<Table<ClientRow>
					rowKey="clientId"
					loading={loading}
					dataSource={rows}
					locale={{
						emptyText: (
							<EmptyState
								purpose="No applications in this project yet. An application is an OAuth client that signs this project's people in or calls an API through this server."
								create={writable ? newClient : undefined}
							/>
						)
					}}
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
							render: (clientName: string | undefined, row: ClientRow) => (
								<Space size={4}>
									{writable && !row.registeredDynamically ? (
										<Typography.Link onClick={() => openEditModal(row)}>
											{clientName || row.clientId}
										</Typography.Link>
									) : (
										<span>{clientName || '—'}</span>
									)}
									{row.registeredDynamically ? (
										<Tag>Self-registered</Tag>
									) : null}
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
						...(writable
							? [
									{
										title: '',
										key: 'actions',
										render: (_: unknown, row: ClientRow) =>
											row.registeredDynamically ? null : (
												<RowActions
													name={row.clientName || row.clientId}
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
				title={mode === 'create' ? 'New application' : 'Edit application'}
				okText={mode === 'create' ? 'Create application' : 'Save'}
				open={open}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				confirmLoading={saving}
				destroyOnHidden
			>
				<Form<FormValues>
					form={form}
					layout="vertical"
					scrollToFirstError
					onFinish={(values) => void onSubmit(values)}
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
						dependencies={['tokenEndpointAuthMethod']}
						rules={[
							{ required: true },
							({ getFieldValue }) => ({
								validator(_, grants: string[] | undefined) {
									const refused = grantRefusedToPublicClient(
										getFieldValue('tokenEndpointAuthMethod'),
										grants ?? []
									);
									return refused
										? Promise.reject(
												new Error(
													`${refused} needs a client that authenticates — choose a token endpoint auth method other than none.`
												)
											)
										: Promise.resolve();
								}
							})
						]}
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
						name="corsOrigins"
						label="Browser origins"
						extra="Web origins whose browser code may call this application's token and userinfo endpoints. Exact match, no wildcards; an empty list allows none."
					>
						<OriginsField
							siblings={rows
								.filter(
									(row) =>
										row.clientId !== editingClientId &&
										(row.corsOrigins?.length ?? 0) > 0
								)
								.map((row) => ({
									label: row.clientName || row.clientId,
									origins: row.corsOrigins ?? []
								}))}
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
					{/* With consent skipped there is no page to choose on, so the switch would mean nothing. */}
					<Form.Item<FormValues>
						shouldUpdate={(prev, cur) =>
							prev.requireConsent !== cur.requireConsent
						}
						noStyle
					>
						{() =>
							form.getFieldValue('requireConsent') ? (
								<Form.Item
									name="partialConsent"
									label="Lets people choose permissions"
									valuePropName="checked"
									extra="People can untick individual permissions on the consent page. Turn on only if this application works with fewer permissions than it asks for."
								>
									<Switch />
								</Form.Item>
							) : null
						}
					</Form.Item>
					<Form.Item
						name="logo"
						label="Logo on the consent page"
						extra="Shown only to people who sign in through this organization’s own project. PNG, JPEG or WebP, up to 64 KiB; square, at least 128 px."
					>
						<LogoField />
					</Form.Item>
					<Form.Item
						name="primaryColor"
						label="Primary colour"
						extra="Used on the sign-in, two-step and consent pages, only for people of this organization’s own projects. Shifted to a darker or lighter shade where the colour itself would be hard to read."
					>
						<PrimaryColorField />
					</Form.Item>
					<Form.Item
						name="policyUri"
						label="Privacy policy URL"
						extra="Linked on the consent page only when it is on the same host as a redirect URI."
					>
						<Input placeholder="https://app.example.com/privacy" />
					</Form.Item>
					<Form.Item
						name="tosUri"
						label="Terms of service URL"
						extra="Linked on the consent page only when it is on the same host as a redirect URI."
					>
						<Input placeholder="https://app.example.com/terms" />
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
			{/*
			 * The value exists only in the answer that created it, so the dialog cannot be dismissed until the
			 * operator says it is stored (specs/084): no Cancel, no close button, no click-away.
			 */}
			<Modal
				title="Client secret"
				open={secret !== null}
				closable={false}
				mask={{ closable: false }}
				keyboard={false}
				okText="Done"
				okButtonProps={{ disabled: !secretStored }}
				onOk={() => {
					setSecret(null);
					setSecretStored(false);
				}}
				cancelButtonProps={{ style: { display: 'none' } }}
			>
				{secret !== null && (
					<SecretReveal
						secret={secret}
						noun="client secret"
						acknowledged={secretStored}
						onAcknowledged={setSecretStored}
						acknowledgement="I've put it into the application's configuration"
					/>
				)}
			</Modal>
		</>
	);
}
