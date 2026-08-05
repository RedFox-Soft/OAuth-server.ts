import { useEffect, useState } from 'react';
import {
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
 * Form prefills only. These have **no runtime effect anywhere** — nothing in the server reads a preset name,
 * and behaviour comes from the stored fields alone. A branch per provider in business logic is exactly what
 * the multi-mode principle forbids; saving an operator from re-typing a well-known issuer is not that.
 */
const PRESETS: Record<string, Partial<ProviderValues>> = {
	Google: {
		id: 'google',
		displayName: 'Google',
		issuer: 'https://accounts.google.com',
		scopes: ['openid', 'email', 'profile'],
		emailTrusted: true
	},
	Microsoft: {
		id: 'microsoft',
		displayName: 'Microsoft',
		issuer: 'https://login.microsoftonline.com/common/v2.0',
		scopes: ['openid', 'email', 'profile'],
		emailClaim: 'email'
	},
	Okta: {
		id: 'okta',
		displayName: 'Okta',
		issuer: 'https://example.okta.com',
		scopes: ['openid', 'email', 'profile']
	},
	Auth0: {
		id: 'auth0',
		displayName: 'Auth0',
		issuer: 'https://example.eu.auth0.com',
		scopes: ['openid', 'email', 'profile']
	},
	Keycloak: {
		id: 'keycloak',
		displayName: 'Keycloak',
		issuer: 'https://keycloak.example.com/realms/main',
		scopes: ['openid', 'email', 'profile']
	}
};

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

	async function load() {
		setLoading(true);
		try {
			const res = await fetch(base);
			setRows(res.ok ? await res.json() : []);
		} finally {
			setLoading(false);
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
				<Button
					icon={<PlusOutlined />}
					onClick={() => {
						setEditing(null);
						form.resetFields();
						setOpen(true);
					}}
				>
					Add provider
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
						<Form.Item label="Start from">
							<Select
								placeholder="a well-known provider (optional)"
								allowClear
								options={Object.keys(PRESETS).map((name) => ({
									label: name,
									value: name
								}))}
								onChange={(name?: string) => {
									if (name) form.setFieldsValue(PRESETS[name] ?? {});
								}}
							/>
						</Form.Item>
					)}
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
						<Input />
					</Form.Item>
					<Form.Item
						name="clientSecret"
						label="Client secret"
						tooltip={
							editing ? 'Leave blank to keep the stored secret.' : undefined
						}
						rules={[{ required: !editing }]}
					>
						<Input.Password placeholder={editing ? 'unchanged' : undefined} />
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
