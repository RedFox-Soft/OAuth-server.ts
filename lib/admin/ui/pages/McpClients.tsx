import { useEffect, useState } from 'react';
import {
	Table,
	Button,
	Modal,
	Form,
	Input,
	Select,
	Space,
	Switch,
	Typography,
	Popconfirm,
	Alert,
	Tag,
	message
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';

/*
 * Which client identities may administer this instance.
 *
 * Two things on this screen are the point rather than decoration.
 *
 * The acknowledgement text is not written here. It comes back from the route's own refusal and is
 * rendered verbatim, so what the administrator agrees to and what the route enforced are the same
 * string — a second copy would be a statement that could drift from the rule.
 *
 * The list is empty on a fresh install and stays empty until someone acts. The empty state says so
 * explicitly, because "nothing is permitted" and "this screen has not loaded" look identical
 * otherwise, and the difference is whether an agent can administer the instance.
 */

interface PermissionView {
	_id: string;
	kind: 'identifier' | 'host';
	requireKeyProof: boolean;
	loopbackAcknowledged: boolean;
	acknowledgedBy?: string;
	createdAt: string;
}

interface FormValues {
	kind: 'identifier' | 'host';
	value: string;
	requireKeyProof: boolean;
}

const KIND_OPTIONS = [
	{ label: 'One client (a document URL)', value: 'identifier' },
	{ label: 'Every client a host publishes', value: 'host' }
];

const DEFAULT_VALUES: FormValues = {
	kind: 'identifier',
	value: '',
	requireKeyProof: false
};

export function McpClients() {
	const base = '/admin/api/mcp/clients';
	const [rows, setRows] = useState<PermissionView[]>([]);
	const [loading, setLoading] = useState(true);
	const [open, setOpen] = useState(false);
	const [saving, setSaving] = useState(false);
	/* The route's own words, shown only once it has refused for want of them. */
	const [acknowledgement, setAcknowledgement] = useState<string | null>(null);
	/*
	 * Which capabilities are not in force, and — the part worth getting right — how much that costs.
	 *
	 * The two flags are NOT equivalent, and an earlier version of this screen said they were. Turning
	 * the surface off stops everything, the reserved client included. Turning document identifiers off
	 * stops only the entries below: the reserved `admin-mcp` client is pre-registered, which is the
	 * mechanism the MCP specification lists *first*, and it never touches a client document. Saying
	 * "nothing here takes effect" in that case would send an operator to fix a setting that is not
	 * their problem.
	 *
	 * Read from the settings API, which this screen may call because it is already super-admin only.
	 */
	const [surfaceOff, setSurfaceOff] = useState<string | null>(null);
	const [documentsOff, setDocumentsOff] = useState<string | null>(null);
	const [form] = Form.useForm<FormValues>();

	async function load() {
		setLoading(true);
		try {
			const res = await fetch(base);
			if (res.ok) setRows((await res.json()) as PermissionView[]);
			await loadCapabilities();
		} finally {
			setLoading(false);
		}
	}

	/*
	 * `values` is the desired state and `changedKeys` names the keys saved but not yet in force, which
	 * is the distinction that matters here: a flag switched on and not restarted looks on and is not.
	 * Both are reported, and differently, because the remedy differs — switch it on, or restart.
	 */
	async function loadCapabilities() {
		const res = await fetch('/admin/api/settings');
		if (!res.ok) return;
		const body = (await res.json()) as {
			values: Record<string, unknown>;
			changedKeys: string[];
		};

		const stateOf = (key: string, off: string) => {
			if (body.values[key] !== true) return off;
			if (body.changedKeys.includes(key)) {
				return `${key} is saved but not in force. Settings apply at boot, so restart the server.`;
			}
			return null;
		};

		setSurfaceOff(
			stateOf(
				'mcp.enabled',
				'mcp.enabled is off, so POST /mcp is not served at all — not for a permitted identity, and not for the reserved admin-mcp client either.'
			)
		);
		setDocumentsOff(
			stateOf(
				'clientIdMetadataDocument.enabled',
				'clientIdMetadataDocument.enabled is off, so a client_id that is an HTTPS URL does not resolve to a client. Entries below cannot take effect until it is on.'
			)
		);
	}
	useEffect(() => {
		load();
	}, []);

	function openModal() {
		setAcknowledgement(null);
		form.resetFields();
		form.setFieldsValue(DEFAULT_VALUES);
		setOpen(true);
	}

	async function submit(acknowledge: boolean) {
		const values = await form.validateFields();
		setSaving(true);
		try {
			const res = await fetch(base, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({
					kind: values.kind,
					value: values.value,
					requireKeyProof: values.requireKeyProof,
					...(acknowledge ? { acknowledgeLoopbackRisk: true } : {})
				})
			});

			if (res.status === 409) {
				const detail = (await res.json().catch(() => null)) as {
					message?: string;
					acknowledgementRequired?: boolean;
				} | null;
				/*
				 * A 409 is two different answers: the risk needs acknowledging, or the identity is already
				 * permitted. The flag tells them apart — matching on the message text would break the
				 * moment the wording improved.
				 */
				if (detail?.acknowledgementRequired) {
					setAcknowledgement(detail.message ?? null);
					return;
				}
				message.error(detail?.message ?? 'already permitted');
				return;
			}
			if (!res.ok) {
				const detail = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				message.error(detail?.message ?? 'could not permit that identity');
				return;
			}

			setOpen(false);
			await load();
		} finally {
			setSaving(false);
		}
	}

	async function setKeyProof(entry: PermissionView, requireKeyProof: boolean) {
		const res = await fetch(`${base}/${encodeURIComponent(entry._id)}`, {
			method: 'PATCH',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ requireKeyProof })
		});
		if (!res.ok) {
			message.error('could not change that requirement');
			return;
		}
		await load();
	}

	async function withdraw(entryId: string) {
		const res = await fetch(`${base}/${encodeURIComponent(entryId)}`, {
			method: 'DELETE'
		});
		if (!res.ok) {
			message.error('could not withdraw that permission');
			return;
		}
		await load();
	}

	return (
		<>
			{surfaceOff ? (
				<Alert
					type="error"
					showIcon
					style={{ marginBottom: 16 }}
					message="No agent can reach this instance at all"
					description={surfaceOff}
				/>
			) : null}
			{documentsOff ? (
				<Alert
					type="warning"
					showIcon
					style={{ marginBottom: 16 }}
					message="Entries below cannot take effect yet"
					description={
						<>
							{documentsOff} The reserved <code>admin-mcp</code> client is
							unaffected — it is pre-registered, which is the mechanism the MCP
							specification lists first, and it never resolves a client
							document.
						</>
					}
				/>
			) : null}
			<Alert
				type="info"
				showIcon
				style={{ marginBottom: 16 }}
				message="Client identities permitted to administer this instance"
				description="An agent connecting with one of these identities acts with the permissions of the administrator who signed in through it. The reserved admin-mcp client works without an entry here. A client that registered itself dynamically can never administer the instance, whatever this list says."
			/>

			<div style={{ marginBottom: 16, textAlign: 'right' }}>
				<Button
					type="primary"
					icon={<PlusOutlined />}
					onClick={openModal}
				>
					Permit an identity
				</Button>
			</div>

			<Table
				rowKey="_id"
				loading={loading}
				dataSource={rows}
				pagination={false}
				locale={{
					emptyText:
						'Nothing is permitted. No agent can administer this instance except through the reserved admin-mcp client.'
				}}
				columns={[
					{
						title: 'Identity',
						dataIndex: '_id',
						render: (value: string, row: PermissionView) => (
							<Space
								direction="vertical"
								size={0}
							>
								<Typography.Text code>{value}</Typography.Text>
								<Space size={4}>
									<Tag>{row.kind === 'host' ? 'whole host' : 'one client'}</Tag>
									{row.loopbackAcknowledged ? (
										<Tag color="orange">loopback risk accepted</Tag>
									) : null}
								</Space>
							</Space>
						)
					},
					{
						title: 'Key proof required',
						dataIndex: 'requireKeyProof',
						render: (requireKeyProof: boolean, row: PermissionView) => (
							<Switch
								checked={requireKeyProof}
								onChange={(next) => setKeyProof(row, next)}
							/>
						)
					},
					{
						title: '',
						render: (_: unknown, row: PermissionView) => (
							<Popconfirm
								title="Withdraw this permission?"
								description="Any agent using this identity is refused on its next call — it does not wait for a token to expire."
								okText="Withdraw"
								onConfirm={() => withdraw(row._id)}
							>
								<Button
									size="small"
									danger
								>
									Withdraw
								</Button>
							</Popconfirm>
						)
					}
				]}
			/>

			<Modal
				open={open}
				title="Permit a client identity"
				onCancel={() => setOpen(false)}
				onOk={() => submit(acknowledgement !== null)}
				confirmLoading={saving}
				okText={acknowledgement ? 'I accept — permit it' : 'Permit'}
				okButtonProps={acknowledgement ? { danger: true } : undefined}
				destroyOnHidden
			>
				<Form
					form={form}
					layout="vertical"
					initialValues={DEFAULT_VALUES}
				>
					<Form.Item
						name="kind"
						label="Scope of the permission"
					>
						<Select options={KIND_OPTIONS} />
					</Form.Item>
					<Form.Item
						name="value"
						label="Identity"
						extra="For one client, the HTTPS URL of its client metadata document. For a whole host, the bare hostname."
						rules={[{ required: true, message: 'an identity is required' }]}
					>
						<Input placeholder="https://app.example.com/oauth/client-metadata.json" />
					</Form.Item>
					<Form.Item
						name="requireKeyProof"
						label="Require proof of a published key"
						valuePropName="checked"
						extra="The client must authenticate with a key it published in its own document. This defeats impersonation of a client that redirects to a local address — but few clients can do it."
					>
						<Switch />
					</Form.Item>
					{acknowledgement ? (
						<Alert
							type="warning"
							showIcon
							message="This needs your acknowledgement"
							description={acknowledgement}
						/>
					) : null}
				</Form>
			</Modal>
		</>
	);
}
