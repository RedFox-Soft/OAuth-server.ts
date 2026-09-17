import { useEffect, useState } from 'react';
import {
	Alert,
	Table,
	Button,
	Modal,
	Form,
	Input,
	Select,
	Switch,
	Space,
	Tag,
	Typography,
	Popconfirm,
	message
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import type { FederationProvider } from '../../../federation/types.js';

/*
 * A bucket's upstream identity providers.
 *
 * Its own component rather than more state in BucketDetail, which is already the per-bucket user surface and
 * long enough. The two share only the bucket id.
 */

interface ProviderValues {
	id: string;
	displayName: string;
	issuer: string;
	clientId: string;
	clientSecret?: string;
	scopes?: string[];
	emailTrusted?: boolean;
	provisioning?: 'jit' | 'existing_only';
	allowedEmailDomains?: string[];
	emailClaim?: string;
	enabled?: boolean;
}

/*
 * What the server says it takes to connect a recognised provider to this bucket.
 *
 * This replaced a browser-side map of form prefills. The prefills were honest about having no runtime
 * effect, but they were a second copy of facts the server now holds — and a copy only the console could
 * read, so an agent got none of it. Everything below is fetched, including the one value nobody can guess.
 */
interface Guidance {
	catalogueId: string;
	displayName: string;
	consoleUrl: string;
	steps: string[];
	credentialLabels: { clientId: string; clientSecret: string };
	clientIdHint: string;
	callbackUri: string;
	callbackStability: 'stable' | 'provisional';
	javascriptOrigins: string[];
	alreadyConnected: boolean;
	existingProviderId?: string;
}

interface ConnectValues {
	clientId: string;
	clientSecret: string;
	allowedEmailDomains?: string[];
}

export function FederationPanel({
	bucketId,
	onChanged
}: {
	bucketId: string;
	/* The bucket's own settings depend on this list — a lockout refusal is easier to understand if the
	 * providers shown are current — so the parent is told when it changes. */
	onChanged?: () => void;
}) {
	const base = `/admin/api/buckets/${encodeURIComponent(bucketId)}/federation`;
	const [rows, setRows] = useState<FederationProvider[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [editing, setEditing] = useState<FederationProvider | null>(null);
	const [saving, setSaving] = useState(false);
	const [form] = Form.useForm<ProviderValues>();
	const [guidance, setGuidance] = useState<Guidance[]>([]);
	const [connecting, setConnecting] = useState<Guidance | null>(null);
	const [connectForm] = Form.useForm<ConnectValues>();

	async function load() {
		setLoading(true);
		try {
			const [providers, catalogue] = await Promise.all([
				fetch(base),
				fetch(`${base}/catalogue`)
			]);
			setRows(providers.ok ? await providers.json() : []);
			setGuidance(
				catalogue.ok ? ((await catalogue.json()).providers ?? []) : []
			);
		} finally {
			setLoading(false);
		}
	}

	/*
	 * The address is the thing an administrator must carry to somebody else's console unchanged, so it is
	 * offered as one action. The failure path still leaves it selectable on the page — a clipboard that
	 * refuses is a browser setting, not a reason to be unable to finish.
	 */
	async function copyCallback(uri: string) {
		try {
			await navigator.clipboard.writeText(uri);
			message.success('callback address copied');
		} catch {
			message.error('could not copy — select the address and copy it by hand');
		}
	}

	async function connect(values: ConnectValues) {
		if (!connecting) return;
		setSaving(true);
		try {
			const ok = await send(base, 'POST', {
				catalogueId: connecting.catalogueId,
				...values
			});
			if (!ok) return;
			setConnecting(null);
			connectForm.resetFields();
			await load();
			onChanged?.();
		} finally {
			setSaving(false);
		}
	}

	useEffect(() => {
		void load();
	}, [bucketId]);

	/* One reporter for every mutation, so the server's reason is what an operator reads. */
	async function send(
		path: string,
		method: string,
		body?: unknown
	): Promise<boolean> {
		const res = await fetch(path, {
			method,
			...(body
				? {
						headers: { 'content-type': 'application/json' },
						body: JSON.stringify(body)
					}
				: {})
		});
		if (res.ok) return true;
		const detail = (await res.json().catch(() => null)) as {
			message?: string;
		} | null;
		message.error(detail?.message ?? `request failed (${res.status})`);
		return false;
	}

	async function submit(values: ProviderValues) {
		setSaving(true);
		try {
			const ok = editing
				? await send(
						`${base}/${encodeURIComponent(editing.id)}`,
						'PATCH',
						// `id` is not editable: it appears in URLs the login page has already rendered.
						{ ...values, id: undefined }
					)
				: await send(base, 'POST', values);
			if (!ok) return;
			setOpen(false);
			setEditing(null);
			form.resetFields();
			await load();
			onChanged?.();
		} finally {
			setSaving(false);
		}
	}

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
					Identity providers
				</Typography.Title>
				{/*
				 * A recognised provider is connected by name; anything else is configured field by field.
				 * Two routes to the same stored record, and the guided one is offered first because it is
				 * the one that can tell an administrator the callback address to register.
				 */}
				{guidance.map((entry) => (
					<Button
						key={entry.catalogueId}
						type="primary"
						onClick={() => {
							connectForm.resetFields();
							setConnecting(entry);
						}}
					>
						{entry.alreadyConnected
							? `${entry.displayName} connected`
							: `Connect ${entry.displayName}`}
					</Button>
				))}
				<Button
					icon={<PlusOutlined />}
					onClick={() => {
						setEditing(null);
						form.resetFields();
						setOpen(true);
					}}
				>
					Add another provider
				</Button>
			</Space>

			<Typography.Paragraph type="secondary">
				Users of this bucket can sign in through these providers. A provider's
				client secret is stored but never shown again.
			</Typography.Paragraph>

			<Table<FederationProvider>
				rowKey="id"
				loading={loading}
				dataSource={rows}
				pagination={false}
				columns={[
					{ title: 'Id', dataIndex: 'id' },
					{ title: 'Name', dataIndex: 'displayName' },
					{ title: 'Issuer', dataIndex: 'issuer' },
					{
						title: 'Status',
						dataIndex: 'enabled',
						render: (enabled: boolean) => (
							<Tag color={enabled ? 'green' : 'default'}>
								{enabled ? 'enabled' : 'disabled'}
							</Tag>
						)
					},
					{
						title: 'Email',
						render: (_, row) => (
							<Space size={4}>
								{row.emailTrusted && <Tag color="blue">trusted</Tag>}
								<Tag>
									{row.provisioning === 'jit' ? 'auto-create' : 'existing only'}
								</Tag>
							</Space>
						)
					},
					{
						title: '',
						render: (_, row) => (
							<Space>
								<Button
									size="small"
									onClick={() => {
										setEditing(row);
										// The masked secret is deliberately not prefilled: an empty field means
										// "keep the stored one", which is what an operator editing a name wants.
										form.setFieldsValue({ ...row, clientSecret: undefined });
										setOpen(true);
									}}
								>
									Edit
								</Button>
								<Button
									size="small"
									onClick={async () => {
										if (
											await send(
												`${base}/${encodeURIComponent(row.id)}`,
												'PATCH',
												{ enabled: !row.enabled }
											)
										) {
											await load();
											onChanged?.();
										}
									}}
								>
									{row.enabled ? 'Disable' : 'Enable'}
								</Button>
								<Popconfirm
									title="Remove this provider?"
									description="Accounts already linked to it keep their other ways to sign in."
									onConfirm={async () => {
										if (
											await send(
												`${base}/${encodeURIComponent(row.id)}`,
												'DELETE'
											)
										) {
											await load();
											onChanged?.();
										}
									}}
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

			{/*
			 * Restated beside the providers it governs, and worded so it claims nothing it cannot prove.
			 * Whether the upstream actually holds this address is the one thing that cannot be checked
			 * without a person completing a sign-in — so the console says where to look rather than
			 * implying the connection has been verified.
			 */}
			{rows.length > 0 && guidance[0] && (
				<div style={{ marginTop: 16 }}>
					<Typography.Paragraph type="secondary">
						Every provider on this bucket returns users to{' '}
						<Typography.Text
							code
							copyable={{ text: guidance[0].callbackUri }}
						>
							{guidance[0].callbackUri}
						</Typography.Text>
						. If a sign-in fails on the provider's own page, that address not
						being registered there is by far the most likely cause.
					</Typography.Paragraph>
					{guidance[0].callbackStability === 'provisional' && (
						<Alert
							type="warning"
							showIcon
							message="This address will change"
							description="This bucket has no address of its own yet, so the address above is built from its internal id. Giving the bucket a slug changes it, and whatever you registered with the provider stops matching. Set the slug first."
						/>
					)}
				</div>
			)}

			{connecting && (
				<Modal
					open
					width={640}
					title={`Connect ${connecting.displayName}`}
					okText={connecting.alreadyConnected ? 'Close' : 'Connect'}
					okButtonProps={{
						style: connecting.alreadyConnected ? { display: 'none' } : undefined
					}}
					confirmLoading={saving}
					onCancel={() => setConnecting(null)}
					onOk={() => connectForm.submit()}
				>
					{connecting.alreadyConnected ? (
						<Alert
							type="info"
							showIcon
							message={`${connecting.displayName} is already connected to this bucket`}
							description={`Edit the provider '${connecting.existingProviderId}' in the table below to change its credentials or settings. A bucket holds one connection per provider.`}
						/>
					) : (
						<>
							<Typography.Paragraph>
								Do this at{' '}
								<Typography.Link
									href={connecting.consoleUrl}
									target="_blank"
									rel="noreferrer"
								>
									{connecting.displayName}
								</Typography.Link>
								, then come back with the two values it gives you.
							</Typography.Paragraph>
							<ol style={{ paddingLeft: 20, marginBottom: 16 }}>
								{connecting.steps.map((step) => (
									<li
										key={step}
										style={{ marginBottom: 6 }}
									>
										{step}
									</li>
								))}
							</ol>

							<Typography.Paragraph style={{ marginBottom: 4 }}>
								<strong>The redirect URI to register</strong>
							</Typography.Paragraph>
							<Space
								align="center"
								style={{ marginBottom: 4 }}
							>
								<Typography.Text code>{connecting.callbackUri}</Typography.Text>
								<Button
									size="small"
									onClick={() => void copyCallback(connecting.callbackUri)}
								>
									Copy
								</Button>
							</Space>
							<Typography.Paragraph type="secondary">
								Paste it exactly. Providers match this address character for
								character, and a mismatch is refused on their page rather than
								here.
							</Typography.Paragraph>
							{connecting.callbackStability === 'provisional' && (
								<Alert
									style={{ marginBottom: 16 }}
									type="warning"
									showIcon
									message="Give this bucket a slug first"
									description="This bucket has no address of its own, so the address above is built from its internal id and will change the moment you assign a slug — silently invalidating what you registered."
								/>
							)}

							<Form
								form={connectForm}
								layout="vertical"
								onFinish={connect}
							>
								{/*
								 * These are an upstream's credentials, never the administrator's own. Without
								 * this the browser reads an identifier beside a secret as a sign-in form and
								 * fills both from its password store, which is both wrong and alarming.
								 */}
								<Form.Item
									name="clientId"
									label={connecting.credentialLabels.clientId}
									tooltip={connecting.clientIdHint}
									rules={[{ required: true }]}
								>
									<Input autoComplete="off" />
								</Form.Item>
								<Form.Item
									name="clientSecret"
									label={connecting.credentialLabels.clientSecret}
									rules={[{ required: true }]}
								>
									<Input.Password autoComplete="new-password" />
								</Form.Item>
								<Form.Item
									name="allowedEmailDomains"
									label="Restrict to these email domains"
									tooltip="Optional. Bare lower-case domains. Empty means anyone with an account at this provider can sign in."
								>
									<Select
										mode="tags"
										tokenSeparators={[' ', ',']}
										placeholder="acme.com"
									/>
								</Form.Item>
							</Form>
						</>
					)}
				</Modal>
			)}

			<Modal
				open={open}
				title={
					editing ? `Edit ${editing.displayName}` : 'Add identity provider'
				}
				okText="Save"
				confirmLoading={saving}
				onCancel={() => {
					setOpen(false);
					setEditing(null);
				}}
				onOk={() => form.submit()}
			>
				<Form
					form={form}
					layout="vertical"
					onFinish={submit}
					initialValues={{
						scopes: ['openid', 'email', 'profile'],
						provisioning: 'jit',
						emailClaim: 'email',
						enabled: true
					}}
				>
					{!editing && (
						<Form.Item
							name="id"
							label="Id"
							tooltip="Appears in the sign-in URL. Lower-case letters, digits and hyphens."
							rules={[{ required: true }]}
						>
							<Input placeholder="acme-sso" />
						</Form.Item>
					)}
					<Form.Item
						name="displayName"
						label="Button label"
						rules={[{ required: true }]}
					>
						<Input placeholder="Acme SSO" />
					</Form.Item>
					<Form.Item
						name="issuer"
						label="Issuer"
						tooltip="Checked when you save: its discovery document must be reachable and name this issuer."
						rules={[{ required: true }]}
					>
						<Input placeholder="https://idp.acme.com" />
					</Form.Item>
					<Form.Item
						name="clientId"
						label="Client id"
						rules={[{ required: !editing }]}
					>
						<Input autoComplete="off" />
					</Form.Item>
					<Form.Item
						name="clientSecret"
						label="Client secret"
						tooltip={
							editing ? 'Leave blank to keep the stored secret.' : undefined
						}
						rules={[{ required: !editing }]}
					>
						{/* Editing means an empty field keeps the stored secret, so an autofilled value here
						    would silently overwrite a working credential with the wrong one. */}
						<Input.Password
							autoComplete="new-password"
							placeholder={editing ? 'unchanged' : undefined}
						/>
					</Form.Item>
					<Form.Item
						name="scopes"
						label="Scopes"
					>
						<Select
							mode="tags"
							tokenSeparators={[' ', ',']}
						/>
					</Form.Item>
					<Form.Item
						name="emailClaim"
						label="Email claim"
						tooltip="Which claim carries the address. Some corporate providers use upn."
					>
						<Input />
					</Form.Item>
					<Form.Item
						name="allowedEmailDomains"
						label="Allowed email domains"
						tooltip="Bare lower-case domains. Empty means any domain is accepted."
					>
						<Select
							mode="tags"
							tokenSeparators={[' ', ',']}
							placeholder="acme.com"
						/>
					</Form.Item>
					<Form.Item
						name="emailTrusted"
						label="Trust this provider's verified addresses"
						tooltip="Only enable for a provider that genuinely verifies addresses. It allows linking to an existing account with the same address."
						valuePropName="checked"
					>
						<Switch />
					</Form.Item>
					<Form.Item
						name="provisioning"
						label="First-time users"
					>
						<Select
							options={[
								{ label: 'Create an account automatically', value: 'jit' },
								{
									label: 'Only allow accounts that already exist',
									value: 'existing_only'
								}
							]}
						/>
					</Form.Item>
					{editing && (
						<Form.Item
							name="enabled"
							label="Enabled"
							valuePropName="checked"
						>
							<Switch />
						</Form.Item>
					)}
				</Form>
			</Modal>
		</div>
	);
}
