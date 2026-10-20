import { useCallback, useEffect, useRef, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	InputNumber,
	Select,
	Space,
	Typography,
	Alert,
	Tag,
	Checkbox,
	Tooltip,
	type FormInstance
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import {
	OMNIBUS_SCOPES,
	SCOPE_DESCRIPTION_MAX_LENGTH
} from '../../../resources/scopes.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { AreaToolbar } from '../frame/AreaToolbar.js';
import { RowActions } from '../frame/RowActions.js';
import { useRoute } from '../frame/router.js';
import { EmptyState, LoadFailed } from '../frame/states.js';
import { atLimit, type PlanView } from '../planText.js';

/*
 * A bucket's APIs — its declared protected resources: the audiences this server will mint tokens for on
 * the bucket's behalf (specs/099).
 *
 * Two things on this screen are not decoration and should survive any redesign.
 *
 * The scope-list warning, because a scope list is not a menu. A client given no scope guidance
 * requests every scope the resource advertises — the MCP specification says so, and says it is
 * deliberate, since a general-purpose agent cannot choose among names it does not understand. So a
 * long list is a grant of the whole list to every client that arrives, and an operator who has not
 * been told that will write one.
 *
 * The revocation window, because the default token format is self-contained. A resource verifies such
 * a token against the published keys with no request back, which is what keeps setup to minutes — and
 * the cost is that revocation waits for expiry. Stating the resulting window next to the lifetime is
 * the difference between a chosen trade-off and a surprise.
 */

const TOKEN_FORMAT_OPTIONS = [
	{
		label: 'Self-contained (verified against this server’s keys)',
		value: 'jwt'
	},
	{ label: 'Opaque (checked back with this server)', value: 'opaque' }
];

type ScopeKind = 'see' | 'act';

interface ResourceView {
	identifier: string;
	name: string;
	scopes: string[];
	scopeDescriptions?: Record<string, { description: string; kind?: ScopeKind }>;
	tokenFormat: 'jwt' | 'opaque';
	accessTokenTTL: number;
	trailingSlashSignificant: boolean;
	/* What the API itself must serve and check, as the server states it (spec 107). */
	connection?: {
		issuer: string;
		audience: string;
		metadata: Record<string, unknown>;
		metadataUrl: string | null;
		challenge: string | null;
	};
}

/* How agent hosts get a client identity here, from the project's own public configuration (spec 107). */
export interface AgentClients {
	urlClientIds: boolean;
	selfRegistration: 'open' | 'token' | 'off';
}

// Form.useWatch is typed as the field's value, but it answers undefined until the field registers.
function useWatched<K extends keyof FormValues>(
	form: FormInstance<FormValues>,
	name: K
): FormValues[K] | undefined {
	return Form.useWatch(name, form);
}

interface FormValues {
	identifier: string;
	name: string;
	scopes: string;
	/* Per scope, what it lets an app do and whether it only sees; keyed by the scope as typed above. */
	descriptions?: Record<string, { description?: string; kind?: ScopeKind }>;
	tokenFormat: 'jwt' | 'opaque';
	// InputNumber answers null once the operator clears it.
	accessTokenTTL: number | null;
	trailingSlashSignificant: boolean;
}

const DEFAULT_VALUES: FormValues = {
	identifier: '',
	name: '',
	scopes: '',
	tokenFormat: 'jwt',
	accessTokenTTL: 900,
	trailingSlashSignificant: false
};

function splitScopes(raw: string): string[] {
	return raw
		.split(/[\s,]+/)
		.map((scope) => scope.trim())
		.filter((scope) => scope.length > 0);
}

/*
 * What the consent page will say about each scope. A row left empty sends nothing for that scope, and the
 * page then shows it by its technical name under "not described" — honest, but no help to the person
 * deciding.
 */
const KIND_OPTIONS: { label: string; value: ScopeKind }[] = [
	{ label: 'Acts for the person', value: 'act' },
	{ label: 'Only lets it see', value: 'see' }
];

function describedScopes(
	scopes: string[],
	descriptions: FormValues['descriptions']
): Record<string, { description: string; kind?: ScopeKind }> {
	const out: Record<string, { description: string; kind?: ScopeKind }> = {};
	for (const scope of scopes) {
		const entry = descriptions?.[scope];
		const description = entry?.description?.trim();
		if (!description) continue;
		out[scope] = { description, ...(entry?.kind ? { kind: entry.kind } : {}) };
	}
	return out;
}

function describeWindow(seconds: number): string {
	if (seconds % 3600 === 0) {
		const hours = seconds / 3600;
		return `${hours} hour${hours === 1 ? '' : 's'}`;
	}
	if (seconds % 60 === 0) {
		const minutes = seconds / 60;
		return `${minutes} minute${minutes === 1 ? '' : 's'}`;
	}
	return `${seconds} seconds`;
}

/*
 * What the operator is told about their scope list, computed from the same `OMNIBUS_SCOPES` the route
 * refuses. Sharing the list is the point: a console warning about a different set than the server
 * enforces would teach the wrong rule.
 */
function scopeAdvice(raw: string): string | null {
	const scopes = splitScopes(raw);
	if (scopes.length === 0) return null;

	const omnibus = scopes.find((scope) =>
		OMNIBUS_SCOPES.includes(scope.toLowerCase())
	);
	if (omnibus) {
		return `${omnibus} will be refused: it grants everything to every client that arrives. Name the scopes the resource actually distinguishes.`;
	}
	if (scopes.length > 4) {
		return `A client given no scope guidance requests all ${scopes.length} of these at once. This list is the baseline for basic use, not a catalogue of everything the resource could ever permit.`;
	}
	return null;
}

interface Vouching {
	status: 'vouched' | 'not_vouched' | 'not_checked';
	step?: 'challenge' | 'path_inserted' | 'root';
	reason?: string;
	expectedIssuer: string;
}

const STEP_LABEL: Record<NonNullable<Vouching['step']>, string> = {
	challenge: 'the 401 challenge',
	path_inserted: 'the path-inserted well-known address',
	root: 'the root well-known address'
};

const REASON_LABEL: Record<string, string> = {
	unreachable: 'the resource could not be reached',
	blocked_address:
		'the resource is on a private address this server does not fetch',
	not_https: 'the resource is not served over https',
	no_metadata: 'no protected resource metadata was found',
	resource_mismatch: 'the metadata describes a different resource',
	issuer_not_listed: 'the metadata does not list this server',
	malformed: 'the metadata is not valid JSON'
};

/*
 * Whether the resource's own metadata vouches for this declaration. Fetched per row once the list is
 * on screen, so a slow resource delays its own cell and nothing else; informational, since nothing is
 * refused on it — it answers why an MCP client might not find this server.
 */
function VouchingCell({ url }: { url: string }) {
	const [vouching, setVouching] = useState<Vouching | null>(null);
	const [checking, setChecking] = useState(true);
	// Every state write follows an await, so the effect below sets nothing synchronously.
	const fetchVouching = useCallback(
		() =>
			request<Vouching>('GET', url).then((result) => {
				setVouching(result.ok ? result.data : null);
				setChecking(false);
			}),
		[url]
	);
	useEffect(() => {
		void fetchVouching();
	}, [fetchVouching]);

	if (checking) return <Tag>checking…</Tag>;
	if (!vouching) return <Tag>unavailable</Tag>;
	const detail =
		vouching.status === 'vouched'
			? `Found through ${STEP_LABEL[vouching.step ?? 'path_inserted']}.`
			: `${REASON_LABEL[vouching.reason ?? ''] ?? 'Metadata not found'}. It must list ${vouching.expectedIssuer} in authorization_servers.`;
	const color =
		vouching.status === 'vouched'
			? 'green'
			: vouching.status === 'not_checked'
				? 'default'
				: 'orange';
	const label =
		vouching.status === 'vouched'
			? 'found'
			: vouching.status === 'not_checked'
				? 'not checked'
				: 'not found';
	return (
		<Tooltip title={detail}>
			<Tag color={color}>{label}</Tag>
		</Tooltip>
	);
}

/*
 * What a developer protecting this API must serve and check (spec 107): the values this server's tokens for it carry,
 * the metadata document an agent host looks for, and the challenge that sends it there — each to copy as it is.
 */
function ResourceConnectionDetails({
	connection
}: {
	connection: NonNullable<ResourceView['connection']>;
}) {
	const copyable = (value: string) => (
		<Typography.Text
			code
			copyable={{ text: value }}
		>
			{value}
		</Typography.Text>
	);
	return (
		<Space
			orientation="vertical"
			size={12}
			style={{ width: '100%' }}
		>
			<div>
				<Typography.Text strong>Issuer</Typography.Text>
				<div>{copyable(connection.issuer)}</div>
			</div>
			<div>
				<Typography.Text strong>Audience (aud) of its tokens</Typography.Text>
				<div>{copyable(connection.audience)}</div>
			</div>
			{connection.metadataUrl && (
				<div>
					<Typography.Text strong>
						Serve this protected resource metadata at
					</Typography.Text>
					<div>{copyable(connection.metadataUrl)}</div>
					<Typography.Paragraph
						copyable={{ text: JSON.stringify(connection.metadata, null, 2) }}
					>
						<pre style={{ margin: 0, whiteSpace: 'pre-wrap' }}>
							{JSON.stringify(connection.metadata, null, 2)}
						</pre>
					</Typography.Paragraph>
				</div>
			)}
			{connection.challenge && (
				<div>
					<Typography.Text strong>
						Answer a request without a valid token with 401 and
					</Typography.Text>
					<div>{copyable(`WWW-Authenticate: ${connection.challenge}`)}</div>
				</div>
			)}
			<div>
				<Typography.Text strong>
					On every request, your server checks
				</Typography.Text>
				<ul style={{ margin: '4px 0 0', paddingInlineStart: 20 }}>
					<li>the token's aud is exactly {connection.audience};</li>
					<li>its iss is {connection.issuer};</li>
					<li>
						its signature verifies against the keys published at{' '}
						{connection.issuer}/jwks;
					</li>
					<li>it is an access token (typ at+jwt), and it has not expired;</li>
					<li>it is never passed on to another service.</li>
				</ul>
			</div>
		</Space>
	);
}

/*
 * Where the bucket's declarations live (specs/085). An identifier is unique within a namespace: the bucket's
 * own when it has an address, the instance's root otherwise — shared with every other root-served bucket.
 */
function namespaceLine(
	bucketName: string,
	namespace: Namespace | null
): string {
	if (namespace === 'project') {
		return `Declared in ${bucketName}'s own namespace: an identifier must be unique within this project.`;
	}
	return "Declared in the instance's shared root namespace, which every project without an address of its own shares.";
}

type Namespace = 'project' | 'root';

/*
 * `canEdit` is the bucket's stated `edit` right. At the root namespace only a super administrator declares,
 * so the screen is writable there for them alone — the server refuses anyone else the same way.
 */
export function Resources({
	bucketId,
	bucketName,
	canEdit,
	superAdmin,
	plan,
	agentClients,
	onChanged
}: {
	bucketId: string;
	bucketName: string;
	canEdit: boolean;
	superAdmin: boolean;
	agentClients?: AgentClients;
	/* The plan the caller is held to (specs/102); null when nothing limits them. */
	plan?: PlanView | null;
	/* An API was declared or removed: the project's counts, and so its plan's use, changed. */
	onChanged?: () => void;
}) {
	const bucketBase = `/admin/api/projects/${encodeURIComponent(bucketId)}`;
	const base = `${bucketBase}/resources`;
	const [namespace, setNamespace] = useState<Namespace | null>(null);
	const writable = canEdit && (namespace === 'project' || superAdmin);
	const [rows, setRows] = useState<ResourceView[]>([]);
	const [loading, setLoading] = useState(true);
	const [loadFailed, setLoadFailed] = useState<string | null>(null);
	const [open, setOpen] = useState(false);
	const [mode, setMode] = useState<'create' | 'edit'>('create');
	const [editing, setEditing] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);
	const [form] = Form.useForm<FormValues>();
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [connecting, setConnecting] = useState<ResourceView | null>(null);
	/* "My MCP server or API" in New application lands here with ?declare=1 (spec 107): open the form once, if allowed. */
	const declareRequested = useRoute().query.get('declare') === '1';
	const declareOffered = useRef(false);

	const scopesValue = useWatched(form, 'scopes') ?? '';
	const ttlValue = useWatched(form, 'accessTokenTTL') ?? 900;
	const formatValue = useWatched(form, 'tokenFormat') ?? 'jwt';

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchResources = useCallback(
		() =>
			request<{ namespace: Namespace; resources: ResourceView[] }>(
				'GET',
				base
			).then((result) => {
				if (result.ok) {
					setNamespace(result.data.namespace);
					setRows(result.data.resources);
					setLoadFailed(null);
					const mayDeclare =
						canEdit && (result.data.namespace === 'project' || superAdmin);
					if (declareRequested && mayDeclare && !declareOffered.current) {
						declareOffered.current = true;
						setMode('create');
						setEditing(null);
						form.resetFields();
						form.setFieldsValue(DEFAULT_VALUES);
						setOpen(true);
					}
				} else {
					setLoadFailed(result.error.message);
				}
				setLoading(false);
			}),
		[base, canEdit, superAdmin, declareRequested, form]
	);
	function load() {
		setLoading(true);
		return fetchResources();
	}
	/*
	 * Reloads when the bucket changes and never on `load` identity — the list belongs to the bucket, not to
	 * the closure.
	 */
	useEffect(() => {
		void fetchResources();
	}, [fetchResources]);

	function openCreateModal() {
		setMode('create');
		setEditing(null);
		form.resetFields();
		form.setFieldsValue(DEFAULT_VALUES);
		setOpen(true);
	}

	function openEditModal(row: ResourceView) {
		setMode('edit');
		setEditing(row.identifier);
		form.setFieldsValue({
			identifier: row.identifier,
			name: row.name,
			scopes: row.scopes.join(' '),
			descriptions: row.scopeDescriptions ?? {},
			tokenFormat: row.tokenFormat,
			accessTokenTTL: row.accessTokenTTL,
			trailingSlashSignificant: row.trailingSlashSignificant
		});
		setOpen(true);
	}

	async function submit(values: FormValues) {
		const scopes = splitScopes(values.scopes);
		const scopeDescriptions = describedScopes(scopes, values.descriptions);
		/*
		 * The identifier is absent from the edit payload deliberately, and the server refuses it if
		 * sent: it is the audience of every token already minted for this resource, so replacing it is
		 * a delete and a fresh declaration rather than a rename.
		 */
		const body =
			mode === 'create'
				? {
						identifier: values.identifier,
						name: values.name,
						scopes,
						...(Object.keys(scopeDescriptions).length
							? { scopeDescriptions }
							: {}),
						tokenFormat: values.tokenFormat,
						accessTokenTTL: values.accessTokenTTL ?? undefined,
						trailingSlashSignificant: values.trailingSlashSignificant
					}
				: {
						name: values.name,
						scopes,
						// The whole map, so a description emptied here is removed rather than kept.
						scopeDescriptions,
						tokenFormat: values.tokenFormat,
						accessTokenTTL: values.accessTokenTTL ?? undefined
					};

		const url =
			mode === 'create'
				? base
				: `${base}/${encodeURIComponent(editing as string)}`;
		setSaving(true);
		const result = await request(
			mode === 'create' ? 'POST' : 'PATCH',
			url,
			body
		);
		setSaving(false);
		if (!result.ok) {
			feedback.failed(result, form);
			return;
		}
		feedback.done(mode === 'create' ? 'Resource declared.' : 'Resource saved.');
		setOpen(false);
		if (mode === 'create') onChanged?.();
		await load();
	}

	async function remove(row: ResourceView) {
		/*
		 * The bucket's own applications may hold machine tokens for the resource, so the question names them
		 * (specs/085, specs/099). A failed read leaves the question without names rather than blocking it.
		 */
		const clients = await request<
			{
				clientId: string;
				clientName?: string;
				registeredDynamically?: boolean;
			}[]
		>('GET', `${bucketBase}/clients`);
		const apps = clients.ok
			? clients.data
					.filter((c) => !c.registeredDynamically)
					.map((c) => c.clientName || c.clientId)
			: [];
		const agreed = await confirm('resource.remove', {
			target: row.name,
			consequences: [
				'Token issuance for this audience stops on the next request.',
				apps.length > 0
					? `These applications can no longer get tokens for it: ${apps.join(', ')}. Their current tokens work until they expire.`
					: 'A live integration loses access as its current tokens expire.'
			]
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(row.identifier)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done('Resource removed.');
		onChanged?.();
		await load();
	}

	const full = atLimit(plan, 'apis');
	const newResource = (
		<Tooltip title={full ?? undefined}>
			<Button
				type="primary"
				icon={<PlusOutlined />}
				disabled={full !== null}
				onClick={openCreateModal}
			>
				New resource
			</Button>
		</Tooltip>
	);

	return (
		<>
			{/*
			 * What a declared resource still needs before an agent host can reach it, stated once here
			 * rather than left to be discovered by a client that fails to connect.
			 *
			 * Not read from the settings API, unlike the Agent access screen: this page is reachable by a
			 * tenant administrator, who may not read instance settings. So it names the dependency
			 * without claiming to know the current value — which is honest, and is the same thing the
			 * guide says.
			 */}
			{agentClients && (
				<Alert
					type={
						agentClients.urlClientIds || agentClients.selfRegistration !== 'off'
							? 'info'
							: 'warning'
					}
					showIcon
					style={{ marginBottom: 16 }}
					title="How agent hosts get in"
					description={`Agent hosts that identify by a URL (Client ID Metadata Document): ${agentClients.urlClientIds ? 'accepted' : 'not accepted'}. Self-registration: ${agentClients.selfRegistration === 'open' ? 'open' : agentClients.selfRegistration === 'token' ? 'with an initial access token' : 'off'}. ${agentClients.urlClientIds || agentClients.selfRegistration !== 'off' ? 'Claude, Cursor and VS Code can connect to the APIs declared here.' : 'An agent host cannot get a client identity here; only applications created in this project can obtain tokens.'}`}
				/>
			)}

			<Typography.Paragraph type="secondary">
				{namespaceLine(bucketName, namespace)}
			</Typography.Paragraph>

			{writable ? (
				<AreaToolbar create={newResource} />
			) : (
				<Alert
					type="info"
					showIcon
					style={{ marginBottom: 16 }}
					title="These APIs are read-only to you"
					description={
						canEdit
							? "This project has no address of its own, so its APIs live in the instance's root namespace, where only a super administrator can declare or change them."
							: "Changing a project's APIs takes membership of the team that owns it."
					}
				/>
			)}

			{loadFailed !== null ? (
				<LoadFailed
					reason={loadFailed}
					onRetry={() => void load()}
				/>
			) : (
				<Table<ResourceView>
					rowKey="identifier"
					loading={loading}
					dataSource={rows}
					pagination={false}
					locale={{
						emptyText: (
							<EmptyState
								purpose="No APIs declared in this project yet. Declare one to have this server mint tokens for its audience."
								create={writable ? newResource : undefined}
							/>
						)
					}}
					columns={[
						{
							title: 'Resource',
							dataIndex: 'identifier',
							render: (identifier: string, row: ResourceView) => (
								<Space
									orientation="vertical"
									size={0}
								>
									{writable ? (
										<Typography.Link
											strong
											onClick={() => openEditModal(row)}
										>
											{row.name}
										</Typography.Link>
									) : (
										<Typography.Text strong>{row.name}</Typography.Text>
									)}
									<Typography.Text code>{identifier}</Typography.Text>
								</Space>
							)
						},
						{
							title: 'Metadata',
							key: 'vouching',
							render: (_: unknown, row: ResourceView) => (
								<VouchingCell
									url={`${base}/${encodeURIComponent(row.identifier)}/vouching`}
								/>
							)
						},
						{
							title: 'Scopes',
							dataIndex: 'scopes',
							render: (scopes: string[]) => (
								<Space
									size={[0, 4]}
									wrap
								>
									{scopes.map((scope) => (
										<Tag key={scope}>{scope}</Tag>
									))}
								</Space>
							)
						},
						{
							title: 'Token',
							dataIndex: 'tokenFormat',
							render: (format: 'jwt' | 'opaque') =>
								format === 'jwt' ? 'Self-contained' : 'Opaque'
						},
						{
							title: 'Lifetime',
							dataIndex: 'accessTokenTTL',
							render: (ttl: number, row: ResourceView) => (
								<Space
									orientation="vertical"
									size={0}
								>
									<span>{describeWindow(ttl)}</span>
									<Typography.Text type="secondary">
										{row.tokenFormat === 'jwt'
											? `revocation takes up to ${describeWindow(ttl)}`
											: 'revocation is immediate'}
									</Typography.Text>
								</Space>
							)
						},
						{
							title: '',
							key: 'connect',
							render: (_: unknown, row: ResourceView) =>
								row.connection ? (
									<Button
										size="small"
										onClick={() => setConnecting(row)}
									>
										Connect
									</Button>
								) : null
						},
						...(writable
							? [
									{
										title: '',
										key: 'actions',
										render: (_: unknown, row: ResourceView) => (
											<RowActions
												name={row.name}
												items={[
													{
														key: 'edit',
														label: 'Edit…',
														group: 'edit',
														onClick: () => openEditModal(row)
													},
													{
														key: 'remove',
														label: 'Remove',
														group: 'danger',
														onClick: () => void remove(row)
													}
												]}
											/>
										)
									}
								]
							: [])
					]}
				/>
			)}

			<Modal
				open={connecting !== null}
				title={connecting ? `Connect ${connecting.name}` : 'Connect'}
				onCancel={() => setConnecting(null)}
				footer={null}
				width={720}
				destroyOnHidden
			>
				{connecting?.connection && (
					<ResourceConnectionDetails connection={connecting.connection} />
				)}
			</Modal>

			<Modal
				open={open}
				title={mode === 'create' ? 'New resource' : 'Edit resource'}
				onCancel={() => setOpen(false)}
				onOk={() => form.submit()}
				confirmLoading={saving}
				okText="Save"
				destroyOnHidden
			>
				<Form
					form={form}
					layout="vertical"
					initialValues={DEFAULT_VALUES}
					scrollToFirstError
					onFinish={(values) => void submit(values)}
				>
					<Form.Item
						name="identifier"
						label="Resource identifier"
						extra="The canonical URI of your MCP server, exactly as its clients will name it — for example https://mcp.example.com/mcp. No fragment. A trailing slash is dropped unless you mark it significant below."
						rules={[{ required: true, message: 'an identifier is required' }]}
					>
						<Input
							placeholder="https://mcp.example.com/mcp"
							disabled={mode === 'edit'}
						/>
					</Form.Item>
					{/*
					 * Off by default because the MCP specification asks clients for the slash-free form; on, the
					 * slash-free spelling becomes a different audience that is not declared.
					 */}
					<Form.Item
						name="trailingSlashSignificant"
						valuePropName="checked"
						extra="Only for a server that really serves a different resource at …/mcp/ than at …/mcp. When on, only the exact spelling is issued tokens."
					>
						<Checkbox disabled={mode === 'edit'}>
							The trailing slash is significant
						</Checkbox>
					</Form.Item>
					{mode === 'edit' && (
						<Alert
							type="info"
							showIcon
							style={{ marginBottom: 16 }}
							title="The identifier cannot be changed"
							description="It is the audience of every token already issued for this resource. Replacing it means removing this declaration and making a new one."
						/>
					)}
					<Form.Item
						name="name"
						label="Name"
						rules={[{ required: true, message: 'a name is required' }]}
					>
						<Input placeholder="Acme MCP" />
					</Form.Item>
					<Form.Item
						name="scopes"
						label="Scopes it recognises"
						extra="Space-separated. The baseline for basic use, not a catalogue."
						rules={[{ required: true, message: 'at least one scope' }]}
					>
						<Input placeholder="mcp:tools-basic mcp:files-read" />
					</Form.Item>
					{splitScopes(scopesValue).length > 0 && (
						<Form.Item
							label="What each scope lets an app do"
							extra="Shown on the consent page after “The app will be able to”: a verb, then what it acts on — “run the service’s tools as you”. A scope left empty is shown only by its name, as not described."
						>
							<Space
								orientation="vertical"
								style={{ width: '100%' }}
							>
								{splitScopes(scopesValue).map((scope) => (
									<Space.Compact
										key={scope}
										style={{ width: '100%' }}
									>
										<Space.Addon>
											<Typography.Text code>{scope}</Typography.Text>
										</Space.Addon>
										<Form.Item
											name={['descriptions', scope, 'description']}
											noStyle
										>
											<Input
												maxLength={SCOPE_DESCRIPTION_MAX_LENGTH}
												placeholder="not described"
											/>
										</Form.Item>
										<Form.Item
											name={['descriptions', scope, 'kind']}
											noStyle
										>
											<Select
												options={KIND_OPTIONS}
												placeholder="Acts for the person"
												style={{ width: 190 }}
												allowClear
											/>
										</Form.Item>
									</Space.Compact>
								))}
							</Space>
						</Form.Item>
					)}
					{scopeAdvice(scopesValue) && (
						<Alert
							type="warning"
							showIcon
							style={{ marginBottom: 16 }}
							title="About this scope list"
							description={scopeAdvice(scopesValue)}
						/>
					)}
					<Form.Item
						name="tokenFormat"
						label="How its tokens are verified"
					>
						<Select options={TOKEN_FORMAT_OPTIONS} />
					</Form.Item>
					<Form.Item
						name="accessTokenTTL"
						label="Access token lifetime (seconds)"
					>
						<InputNumber
							min={30}
							max={86400}
							precision={0}
							style={{ width: '100%' }}
						/>
					</Form.Item>
					<Alert
						type="info"
						showIcon
						title={
							formatValue === 'jwt'
								? `Revocation takes up to ${describeWindow(ttlValue)}`
								: 'Revocation is immediate'
						}
						description={
							formatValue === 'jwt'
								? 'A self-contained token is verified against this server’s published keys with no request back, so your resource needs no credentials of its own — and a revoked token stays valid until it expires. Shorten the lifetime to narrow that window.'
								: 'An opaque token is checked back with this server on every request, so revocation is immediate. Your resource needs credentials of its own and token introspection must be enabled.'
						}
					/>
				</Form>
			</Modal>
		</>
	);
}
