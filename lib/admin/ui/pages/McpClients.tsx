import { useCallback, useEffect, useState } from 'react';
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
	Alert,
	Tag
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { PageHeader } from '../frame/PageHeader.js';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { useConfirm } from '../frame/confirm.js';
import { RowActions } from '../frame/RowActions.js';
import { EmptyState, LoadFailed } from '../frame/states.js';

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
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [rows, setRows] = useState<PermissionView[]>([]);
	const [loading, setLoading] = useState(true);
	const [failed, setFailed] = useState<string | null>(null);
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

	/*
	 * `values` is the desired state; the two key lists name what is stored and not in force here, which
	 * is the distinction that matters on this page — a flag switched on and not applied looks on and is
	 * not. Both are reported, and separately, because the remedy differs: switch it on, restart, or
	 * look at the instance that did apply it.
	 */
	const loadCapabilities = useCallback(async () => {
		const result = await request<{
			values: Record<string, unknown>;
			pendingRestartKeys: string[];
			notInForceKeys: string[];
		}>('GET', '/admin/api/settings');
		if (!result.ok) return;
		const body = result.data;

		const stateOf = (key: string, off: string) => {
			if (body.values[key] !== true) return off;
			if (body.pendingRestartKeys.includes(key)) {
				return `${key} is saved but cannot be applied to a running server. Restart it.`;
			}
			if (body.notInForceKeys.includes(key)) {
				return `${key} is saved but not in force on this instance.`;
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
	}, []);

	// Every state write follows an await, so the mount effect calls this without setting
	// `loading` first; `load` is the reload, which does.
	const fetchPermissions = useCallback(async () => {
		try {
			const result = await request<PermissionView[]>('GET', base);
			if (!result.ok) {
				setFailed(result.error.message);
				return;
			}
			setFailed(null);
			setRows(result.data);
			await loadCapabilities();
		} finally {
			setLoading(false);
		}
	}, [loadCapabilities]);
	function load() {
		setLoading(true);
		return fetchPermissions();
	}
	useEffect(() => {
		void fetchPermissions();
	}, [fetchPermissions]);

	function openModal() {
		setAcknowledgement(null);
		form.resetFields();
		form.setFieldsValue(DEFAULT_VALUES);
		setOpen(true);
	}

	async function submit(acknowledge: boolean) {
		// An invalid form already shows its own errors; a rejection here would only reach the console log.
		const values = await form.validateFields().catch(() => null);
		if (!values) return;
		setSaving(true);
		try {
			const result = await request<PermissionView>('POST', base, {
				kind: values.kind,
				value: values.value,
				requireKeyProof: values.requireKeyProof,
				...(acknowledge ? { acknowledgeLoopbackRisk: true } : {})
			});

			if (!result.ok) {
				/*
				 * A 409 is two different answers: the risk needs acknowledging, or the identity is already
				 * permitted. The flag tells them apart — matching on the message text would break the
				 * moment the wording improved.
				 *
				 * The acknowledgement is this act's C2 confirmation (`agentAccess.permit`), asked inside the
				 * form rather than in a dialog over it: the route's own words, and a danger OK button.
				 */
				if (result.status === 409 && result.error.acknowledgementRequired) {
					setAcknowledgement(result.error.message);
					return;
				}
				feedback.failed(result, form);
				return;
			}

			feedback.done(`Agent identity ${values.value} permitted.`);
			setOpen(false);
			await load();
		} finally {
			setSaving(false);
		}
	}

	async function setKeyProof(entry: PermissionView, requireKeyProof: boolean) {
		const yes = await confirm('agentAccess.keyProof', {
			target: entry._id,
			consequences: requireKeyProof
				? [
						'An agent using this identity must authenticate with a key published in its client document; one that cannot is refused on its next call.'
					]
				: [
						'This identity is accepted without proof of a published key, so a client that redirects to a local address can be impersonated.'
					]
		});
		if (!yes) return;
		const result = await request(
			'PATCH',
			`${base}/${encodeURIComponent(entry._id)}`,
			{ requireKeyProof }
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(
			requireKeyProof
				? `Key proof now required for ${entry._id}.`
				: `Key proof no longer required for ${entry._id}.`
		);
		await load();
	}

	async function withdraw(entry: PermissionView) {
		const yes = await confirm('agentAccess.withdraw', {
			target: entry._id,
			consequences: [
				'Any agent using this identity is refused on its next call — it does not wait for a token to expire.'
			]
		});
		if (!yes) return;
		const result = await request(
			'DELETE',
			`${base}/${encodeURIComponent(entry._id)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`Agent identity ${entry._id} withdrawn.`);
		await load();
	}

	const permit = (
		<Button
			type="primary"
			icon={<PlusOutlined />}
			onClick={openModal}
		>
			Permit an identity
		</Button>
	);

	return (
		<>
			<PageHeader
				title="Agent access"
				actions={permit}
			/>
			{surfaceOff ? (
				<Alert
					type="error"
					showIcon
					style={{ marginBottom: 16 }}
					title="No agent can reach this instance at all"
					description={surfaceOff}
				/>
			) : null}
			{documentsOff ? (
				<Alert
					type="warning"
					showIcon
					style={{ marginBottom: 16 }}
					title="Entries below cannot take effect yet"
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
				title="Client identities permitted to administer this instance"
				description="An agent connecting with one of these identities acts with the permissions of the administrator who signed in through it. The reserved admin-mcp client works without an entry here. A client that registered itself dynamically can never administer the instance, whatever this list says."
			/>

			{failed !== null ? (
				<LoadFailed
					reason={failed}
					onRetry={() => void load()}
				/>
			) : (
				<Table
					rowKey="_id"
					loading={loading}
					dataSource={rows}
					pagination={false}
					locale={{
						emptyText: (
							<EmptyState
								purpose="Nothing is permitted. No agent can administer this instance except through the reserved admin-mcp client."
								create={permit}
							/>
						)
					}}
					columns={[
						{
							title: 'Identity',
							dataIndex: '_id',
							render: (value: string, row: PermissionView) => (
								<Space
									orientation="vertical"
									size={0}
								>
									<Typography.Text code>{value}</Typography.Text>
									<Space size={4}>
										<Tag>
											{row.kind === 'host' ? 'whole host' : 'one client'}
										</Tag>
										{row.loopbackAcknowledged ? (
											<Tag color="orange">loopback risk accepted</Tag>
										) : null}
									</Space>
								</Space>
							)
						},
						{
							title: 'Key proof',
							dataIndex: 'requireKeyProof',
							render: (requireKeyProof: boolean) =>
								requireKeyProof ? (
									<Tag color="blue">Required</Tag>
								) : (
									<Tag>Not required</Tag>
								)
						},
						{
							title: '',
							key: 'actions',
							render: (_: unknown, row: PermissionView) => (
								<RowActions
									name={row._id}
									items={[
										{
											key: 'keyProof',
											label: row.requireKeyProof
												? 'Stop requiring key proof…'
												: 'Require key proof…',
											group: 'state',
											onClick: () => void setKeyProof(row, !row.requireKeyProof)
										},
										{
											key: 'withdraw',
											label: 'Withdraw…',
											group: 'danger',
											onClick: () => void withdraw(row)
										}
									]}
								/>
							)
						}
					]}
				/>
			)}

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
					scrollToFirstError
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
							title="This needs your acknowledgement"
							description={acknowledgement}
						/>
					) : null}
				</Form>
			</Modal>
		</>
	);
}
