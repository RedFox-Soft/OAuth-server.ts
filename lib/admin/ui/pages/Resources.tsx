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
	Alert,
	Tag,
	Checkbox,
	Tooltip,
	message
} from 'antd';
import { PlusOutlined, ArrowLeftOutlined } from '@ant-design/icons';
import type { Project } from '../../../adapters/types.js';
import { OMNIBUS_SCOPES } from '../../../resources/scopes.js';

/*
 * A project's protected resources: the audiences this server will mint tokens for on the project's
 * behalf.
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

interface ResourceView {
	identifier: string;
	name: string;
	scopes: string[];
	tokenFormat: 'jwt' | 'opaque';
	accessTokenTTL: number;
	trailingSlashSignificant: boolean;
}

interface FormValues {
	identifier: string;
	name: string;
	scopes: string;
	tokenFormat: 'jwt' | 'opaque';
	accessTokenTTL: number;
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
	const fetchVouching = useCallback(async () => {
		try {
			const res = await fetch(url);
			setVouching(res.ok ? ((await res.json()) as Vouching) : null);
		} finally {
			setChecking(false);
		}
	}, [url]);
	useEffect(() => {
		void fetchVouching();
	}, [fetchVouching]);

	if (checking) return <Tag>checking…</Tag>;
	if (!vouching) return <Tag>unavailable</Tag>;
	const detail =
		vouching.status === 'vouched'
			? `Found through ${STEP_LABEL[vouching.step ?? 'path_inserted']}.`
			: `${REASON_LABEL[vouching.reason ?? ''] ?? 'not vouched'}. It must list ${vouching.expectedIssuer} in authorization_servers.`;
	const color =
		vouching.status === 'vouched'
			? 'green'
			: vouching.status === 'not_checked'
				? 'default'
				: 'orange';
	const label =
		vouching.status === 'vouched'
			? 'vouched'
			: vouching.status === 'not_checked'
				? 'not checked'
				: 'not vouched';
	return (
		<Tooltip title={detail}>
			<Tag color={color}>{label}</Tag>
		</Tooltip>
	);
}

export function Resources({
	project,
	onBack
}: {
	project: Project;
	onBack: () => void;
}) {
	const base = `/admin/api/projects/${project._id}/resources`;
	const [rows, setRows] = useState<ResourceView[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [mode, setMode] = useState<'create' | 'edit'>('create');
	const [editing, setEditing] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);
	const [form] = Form.useForm<FormValues>();

	const scopesValue = Form.useWatch('scopes', form) ?? '';
	const ttlValue = Form.useWatch('accessTokenTTL', form) ?? 900;
	const formatValue = Form.useWatch('tokenFormat', form) ?? 'jwt';

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchResources = useCallback(async () => {
		try {
			const res = await fetch(base);
			if (res.ok) setRows((await res.json()) as ResourceView[]);
		} finally {
			setLoading(false);
		}
	}, [base]);
	function load() {
		setLoading(true);
		return fetchResources();
	}
	/*
	 * Reloads when the project changes and never on `load` identity — the list belongs to the project,
	 * not to the closure. No exhaustive-deps disable comment: that rule is not configured in this
	 * repository, so the comment would only be an inert lint error (as it is in `Clients.tsx`).
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
			tokenFormat: row.tokenFormat,
			accessTokenTTL: row.accessTokenTTL,
			trailingSlashSignificant: row.trailingSlashSignificant
		});
		setOpen(true);
	}

	async function submit() {
		const values = await form.validateFields();
		setSaving(true);
		try {
			const scopes = splitScopes(values.scopes);
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
							tokenFormat: values.tokenFormat,
							accessTokenTTL: values.accessTokenTTL,
							trailingSlashSignificant: values.trailingSlashSignificant
						}
					: {
							name: values.name,
							scopes,
							tokenFormat: values.tokenFormat,
							accessTokenTTL: values.accessTokenTTL
						};

			const url =
				mode === 'create'
					? base
					: `${base}/${encodeURIComponent(editing as string)}`;
			const res = await fetch(url, {
				method: mode === 'create' ? 'POST' : 'PATCH',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(body)
			});

			if (!res.ok) {
				const detail = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				message.error(detail?.message ?? 'could not save the resource');
				return;
			}
			setOpen(false);
			await load();
		} finally {
			setSaving(false);
		}
	}

	async function remove(identifier: string) {
		const res = await fetch(`${base}/${encodeURIComponent(identifier)}`, {
			method: 'DELETE'
		});
		if (!res.ok) {
			message.error('could not remove the resource');
			return;
		}
		await load();
	}

	return (
		<>
			<Space style={{ marginBottom: 16 }}>
				<Button
					icon={<ArrowLeftOutlined />}
					onClick={onBack}
				>
					Back
				</Button>
				<Typography.Text strong>{project.name}</Typography.Text>
				<Typography.Text type="secondary">protected resources</Typography.Text>
			</Space>

			{/*
			 * What a declared resource still needs before an agent host can reach it, stated once here
			 * rather than left to be discovered by a client that fails to connect.
			 *
			 * Not read from the settings API, unlike the Agent access screen: this page is reachable by a
			 * project administrator, who may not read instance settings. So it names the dependency
			 * without claiming to know the current value — which is honest, and is the same thing the
			 * guide says.
			 */}
			<Alert
				type="info"
				showIcon
				style={{ marginBottom: 16 }}
				message="A declared resource is half of the setup"
				description="Declaring the resource is what makes this server mint tokens for it. For an agent host to obtain one it also needs a client identity: either clientIdMetadataDocument.enabled, so a client_id that is an HTTPS URL is accepted, or registration.enabled for an older host that registers itself. Both are instance settings and both are off by default."
			/>

			<div style={{ marginBottom: 16, textAlign: 'right' }}>
				<Button
					type="primary"
					icon={<PlusOutlined />}
					onClick={openCreateModal}
				>
					Declare a resource
				</Button>
			</div>

			<Table
				rowKey="identifier"
				loading={loading}
				dataSource={rows}
				pagination={false}
				columns={[
					{
						title: 'Resource',
						dataIndex: 'identifier',
						render: (identifier: string, row: ResourceView) => (
							<Space
								direction="vertical"
								size={0}
							>
								<Typography.Text strong>{row.name}</Typography.Text>
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
								direction="vertical"
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
						render: (_: unknown, row: ResourceView) => (
							<Space>
								<Button
									size="small"
									onClick={() => openEditModal(row)}
								>
									Edit
								</Button>
								<Popconfirm
									title="Remove this resource?"
									description="Token issuance for this audience stops on the next request. A live integration loses access as its current tokens expire."
									okText="Remove"
									onConfirm={() => remove(row.identifier)}
								>
									<Button
										size="small"
										danger
									>
										Remove
									</Button>
								</Popconfirm>
							</Space>
						)
					}
				]}
			/>

			<Modal
				open={open}
				title={mode === 'create' ? 'Declare a resource' : 'Edit resource'}
				onCancel={() => setOpen(false)}
				onOk={submit}
				confirmLoading={saving}
				okText="Save"
				destroyOnHidden
			>
				<Form
					form={form}
					layout="vertical"
					initialValues={DEFAULT_VALUES}
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
							message="The identifier cannot be changed"
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
					{scopeAdvice(scopesValue) && (
						<Alert
							type="warning"
							showIcon
							style={{ marginBottom: 16 }}
							message="About this scope list"
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
						<Input
							type="number"
							min={30}
							max={86400}
						/>
					</Form.Item>
					<Alert
						type="info"
						showIcon
						message={
							formatValue === 'jwt'
								? `Revocation takes up to ${describeWindow(Number(ttlValue) || 900)}`
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
