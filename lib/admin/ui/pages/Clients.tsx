import { useEffect, useState } from 'react';
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
	{ label: 'client_secret_post', value: 'client_secret_post' }
];
const CIBA_GRANT_TYPE = 'urn:openid:params:grant-type:ciba';
const CIBA_DELIVERY_MODE_OPTIONS = [
	{ label: 'poll', value: 'poll' },
	{ label: 'ping', value: 'ping' },
	{ label: 'push', value: 'push' }
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
	backchannelTokenDeliveryMode?: 'poll' | 'ping' | 'push';
	backchannelClientNotificationEndpoint?: string;
}
interface FormValues {
	clientName?: string;
	applicationType: 'web' | 'native';
	grantTypes: string[];
	tokenEndpointAuthMethod: string;
	redirectUris?: string;
	scope?: string;
	requireConsent: boolean;
	backchannelTokenDeliveryMode?: 'poll' | 'ping' | 'push';
	backchannelClientNotificationEndpoint?: string;
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
	const [rows, setRows] = useState<ClientView[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [mode, setMode] = useState<'create' | 'edit'>('create');
	const [editingClientId, setEditingClientId] = useState<string | null>(null);
	const [saving, setSaving] = useState(false);
	const [secret, setSecret] = useState<string | null>(null);
	const [form] = Form.useForm<FormValues>();

	async function load() {
		setLoading(true);
		try {
			const res = await fetch(base);
			if (res.ok) setRows((await res.json()) as ClientView[]);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [project._id]);

	function openCreateModal() {
		setMode('create');
		setEditingClientId(null);
		form.resetFields();
		setOpen(true);
	}

	function openEditModal(row: ClientView) {
		setMode('edit');
		setEditingClientId(row.clientId);
		form.setFieldsValue({
			clientName: row.clientName,
			applicationType: row.applicationType as 'web' | 'native',
			grantTypes: row.grantTypes,
			tokenEndpointAuthMethod: row.tokenEndpointAuthMethod,
			redirectUris: (row.redirectUris ?? []).join('\n'),
			scope: row.scope,
			requireConsent: row.requireConsent,
			backchannelTokenDeliveryMode: row.backchannelTokenDeliveryMode,
			backchannelClientNotificationEndpoint:
				row.backchannelClientNotificationEndpoint
		});
		setOpen(true);
	}

	function buildBody(values: FormValues) {
		return {
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
		const body = (await res.json().catch(() => null)) as
			| { message?: string; secret?: string }
			| null;
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
			body: JSON.stringify(buildBody(values))
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
		const res = await fetch(
			`${base}/${encodeURIComponent(clientId)}/secret`,
			{ method: 'POST' }
		);
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
			<Space style={{ marginBottom: 16, justifyContent: 'space-between', width: '100%' }}>
				<Button icon={<ArrowLeftOutlined />} onClick={onBack}>
					Projects
				</Button>
				<Typography.Title level={4} style={{ margin: 0 }}>
					{project.name} — clients
				</Typography.Title>
				<Button type="primary" icon={<PlusOutlined />} onClick={openCreateModal}>
					New client
				</Button>
			</Space>
			<Table<ClientView>
				rowKey="clientId"
				loading={loading}
				dataSource={rows}
				columns={[
					{ title: 'Name', dataIndex: 'clientName' },
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
								<Button size="small" onClick={() => openEditModal(row)}>
									Edit
								</Button>
								{row.tokenEndpointAuthMethod !== 'none' && (
									<Button size="small" onClick={() => onRotate(row.clientId)}>
										Rotate secret
									</Button>
								)}
								<Popconfirm
									title="Delete this client?"
									onConfirm={() => onDelete(row.clientId)}
								>
									<Button size="small" danger>
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
					<Form.Item name="clientName" label="Name">
						<Input />
					</Form.Item>
					<Form.Item name="applicationType" label="Application type">
						<Select
							options={[
								{ label: 'web', value: 'web' },
								{ label: 'native', value: 'native' }
							]}
						/>
					</Form.Item>
					<Form.Item name="grantTypes" label="Grant types" rules={[{ required: true }]}>
						<Select mode="multiple" options={GRANT_OPTIONS} />
					</Form.Item>
					<Form.Item name="tokenEndpointAuthMethod" label="Token endpoint auth">
						<Select options={AUTH_OPTIONS} />
					</Form.Item>
					<Form.Item name="redirectUris" label="Redirect URIs (one per line)">
						<Input.TextArea rows={3} placeholder="https://app.example.com/cb" />
					</Form.Item>
					<Form.Item name="scope" label="Scope">
						<Input placeholder="openid profile email" />
					</Form.Item>
					<Form.Item name="requireConsent" label="Require consent" valuePropName="checked">
						<Switch />
					</Form.Item>
					<Form.Item shouldUpdate={(prev, cur) => prev.grantTypes !== cur.grantTypes}>
						{() => {
							const grantTypes: string[] =
								form.getFieldValue('grantTypes') ?? [];
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
				<Typography.Paragraph copyable code>
					{secret}
				</Typography.Paragraph>
			</Modal>
		</>
	);
}
