import { useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Drawer,
	Empty,
	Flex,
	Form,
	Input,
	Select,
	Switch,
	Table,
	Typography
} from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { request } from '../../frame/request.js';
import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { SecretReveal } from '../../frame/SecretReveal.js';

/*
 * Applications in the administrators' project (specs/109): a super administrator registers one for an internal
 * tool so it can sign the instance's administrators in. Every rule is the server's; this panel only edits the
 * record and shows what the server said when it refuses.
 */

const BASE = '/admin/api/administrators/applications';

interface ApplicationView {
	clientId: string;
	clientName?: string;
	redirectUris: string[];
	postLogoutRedirectUris: string[];
	tokenEndpointAuthMethod: string;
	refreshTokens: boolean;
	requireConsent: boolean;
	hasSecret: boolean;
	issuer: string;
	discoveryUrl: string;
	lastUsed: number | null;
}

interface ApplicationForm {
	clientName: string;
	redirectUris: string;
	postLogoutRedirectUris?: string;
	tokenEndpointAuthMethod: string;
	refreshTokens: boolean;
	requireConsent: boolean;
}

const AUTH_METHODS = [
	{ value: 'client_secret_basic', label: 'Client secret in the header' },
	{ value: 'client_secret_post', label: 'Client secret in the body' },
	{ value: 'private_key_jwt', label: 'Private key JWT' }
];

const lines = (text: string | undefined) =>
	(text ?? '')
		.split('\n')
		.map((line) => line.trim())
		.filter(Boolean);

function formOf(view: ApplicationView | null): ApplicationForm {
	return {
		clientName: view?.clientName ?? '',
		redirectUris: view?.redirectUris.join('\n') ?? '',
		postLogoutRedirectUris: view?.postLogoutRedirectUris.join('\n') ?? '',
		tokenEndpointAuthMethod:
			view?.tokenEndpointAuthMethod ?? 'client_secret_basic',
		refreshTokens: view?.refreshTokens ?? true,
		requireConsent: view?.requireConsent ?? false
	};
}

function bodyOf(values: ApplicationForm) {
	return {
		clientName: values.clientName,
		redirectUris: lines(values.redirectUris),
		postLogoutRedirectUris: lines(values.postLogoutRedirectUris),
		tokenEndpointAuthMethod: values.tokenEndpointAuthMethod,
		refreshTokens: values.refreshTokens,
		requireConsent: values.requireConsent
	};
}

const nameOf = (view: Pick<ApplicationView, 'clientName' | 'clientId'>) =>
	view.clientName ?? view.clientId;

export function ApplicationsPanel() {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [applications, setApplications] = useState<ApplicationView[] | null>(
		null
	);
	const [editing, setEditing] = useState<ApplicationView | 'new' | null>(null);
	const [secret, setSecret] = useState<{ name: string; value: string } | null>(
		null
	);
	const [acknowledged, setAcknowledged] = useState(false);

	// Bumped to load the list again after a change.
	const [version, setVersion] = useState(0);
	const reload = () => setVersion((v) => v + 1);
	useEffect(() => {
		let live = true;
		void request<{ applications: ApplicationView[] }>('GET', BASE).then(
			(result) => {
				if (!live) return;
				if (result.ok) setApplications(result.data.applications);
				else feedback.failed(result);
			}
		);
		return () => {
			live = false;
		};
	}, [feedback, version]);

	function showSecret(name: string, value: string) {
		setAcknowledged(false);
		setSecret({ name, value });
	}

	async function rotate(view: ApplicationView) {
		const agreed = await confirm('adminApplication.rotate', {
			target: nameOf(view),
			consequences: [
				'The current secret stops working at once: update the tool before it next signs someone in.'
			]
		});
		if (!agreed) return;
		const result = await request<{ secret: string }>(
			'POST',
			`${BASE}/${encodeURIComponent(view.clientId)}/secret`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		setEditing(null);
		showSecret(nameOf(view), result.data.secret);
	}

	async function remove(view: ApplicationView) {
		const agreed = await confirm('adminApplication.delete', {
			target: nameOf(view),
			consequences: [
				'Administrators can no longer sign in to it.',
				'Its tokens stop working.'
			]
		});
		if (!agreed) return;
		const result = await request(
			'DELETE',
			`${BASE}/${encodeURIComponent(view.clientId)}`
		);
		if (!result.ok) {
			feedback.failed(result);
			return;
		}
		feedback.done(`${nameOf(view)} deleted.`);
		setEditing(null);
		reload();
	}

	return (
		<Flex
			vertical
			gap={16}
		>
			<Typography.Paragraph type="secondary">
				Let your own internal tools sign in the people who administer this
				instance. A tool registered here receives an administrator&apos;s
				identity and the names of their teams — nothing that acts inside this
				server.
			</Typography.Paragraph>
			{secret && (
				<Card
					size="small"
					title={`The secret of ${secret.name}`}
				>
					<Flex
						vertical
						gap={8}
					>
						<SecretReveal
							secret={secret.value}
							noun="client secret"
							acknowledged={acknowledged}
							onAcknowledged={setAcknowledged}
							acknowledgement="I've put it into the tool's configuration"
						/>
						<Button
							disabled={!acknowledged}
							onClick={() => setSecret(null)}
						>
							Done — hide the secret
						</Button>
					</Flex>
				</Card>
			)}
			<Flex justify="end">
				<Button
					type="primary"
					icon={<PlusOutlined />}
					onClick={() => setEditing('new')}
				>
					Register application
				</Button>
			</Flex>
			<Table
				rowKey="clientId"
				loading={applications === null}
				dataSource={applications ?? []}
				pagination={false}
				locale={{
					emptyText: (
						<Empty description="No internal tool signs administrators in yet." />
					)
				}}
				onRow={(view) => ({ onClick: () => setEditing(view) })}
				columns={[
					{
						title: 'Name',
						key: 'name',
						render: (_, view) => nameOf(view)
					},
					{
						title: 'Client ID',
						key: 'clientId',
						render: (_, view) => (
							<Typography.Text code>{view.clientId}</Typography.Text>
						)
					},
					{
						title: 'Last used',
						key: 'lastUsed',
						render: (_, view) =>
							view.lastUsed === null
								? 'Never'
								: new Date(view.lastUsed * 1000).toLocaleString()
					}
				]}
			/>
			{editing !== null && (
				<ApplicationEditor
					application={editing === 'new' ? null : editing}
					onClose={() => setEditing(null)}
					onRotate={rotate}
					onDelete={remove}
					onSaved={(view, newSecret) => {
						setEditing(null);
						if (newSecret) showSecret(nameOf(view), newSecret);
						reload();
					}}
				/>
			)}
		</Flex>
	);
}

function ApplicationEditor({
	application,
	onClose,
	onRotate,
	onDelete,
	onSaved
}: {
	application: ApplicationView | null;
	onClose: () => void;
	onRotate: (view: ApplicationView) => Promise<void>;
	onDelete: (view: ApplicationView) => Promise<void>;
	onSaved: (view: ApplicationView, secret?: string) => void;
}) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const [form] = Form.useForm<ApplicationForm>();
	const [saving, setSaving] = useState(false);
	const [refusal, setRefusal] = useState<string | null>(null);

	async function save() {
		let values: ApplicationForm;
		try {
			values = await form.validateFields();
		} catch {
			return;
		}
		if (!application) {
			const agreed = await confirm('adminApplication.create', {
				target: values.clientName,
				consequences: [
					'Administrators will be able to sign in to it.',
					'It will receive their identity and the names of their teams.'
				]
			});
			if (!agreed) return;
		}
		setSaving(true);
		setRefusal(null);
		try {
			const result = application
				? await request<ApplicationView>(
						'PATCH',
						`${BASE}/${encodeURIComponent(application.clientId)}`,
						bodyOf(values)
					)
				: await request<ApplicationView & { secret?: string }>(
						'POST',
						BASE,
						bodyOf(values)
					);
			if (!result.ok) {
				if (result.status >= 500) feedback.failed(result);
				else setRefusal(result.error.message);
				return;
			}
			const { secret, ...view } = result.data as ApplicationView & {
				secret?: string;
			};
			feedback.done(`${nameOf(view)} saved.`);
			onSaved(view, secret);
		} finally {
			setSaving(false);
		}
	}

	return (
		<Drawer
			open
			size="large"
			title={
				application ? `Edit ${nameOf(application)}` : 'Register an application'
			}
			onClose={onClose}
			extra={
				<Button
					type="primary"
					loading={saving}
					onClick={() => void save()}
				>
					Save
				</Button>
			}
		>
			{refusal && (
				<Alert
					type="error"
					showIcon
					title="Not saved"
					description={refusal}
					style={{ marginBottom: 16 }}
				/>
			)}
			<Form
				form={form}
				layout="vertical"
				initialValues={formOf(application)}
			>
				<Form.Item
					name="clientName"
					label="Name"
					rules={[{ required: true, message: 'Name the application' }]}
				>
					<Input placeholder="FoxTrust" />
				</Form.Item>
				<Form.Item
					name="redirectUris"
					label="Redirect URIs (one per line)"
					rules={[
						{ required: true, message: 'Enter at least one redirect URI' }
					]}
				>
					<Input.TextArea
						rows={3}
						placeholder="https://tool.example.com/auth/callback"
					/>
				</Form.Item>
				<Form.Item
					name="postLogoutRedirectUris"
					label="Sign-out return URIs (one per line)"
				>
					<Input.TextArea
						rows={2}
						placeholder="https://tool.example.com/"
					/>
				</Form.Item>
				<Form.Item
					name="tokenEndpointAuthMethod"
					label="How the tool authenticates"
				>
					<Select options={AUTH_METHODS} />
				</Form.Item>
				<Form.Item
					name="refreshTokens"
					label="Issue refresh tokens"
					valuePropName="checked"
				>
					<Switch />
				</Form.Item>
				<Form.Item
					name="requireConsent"
					label="Ask for consent"
					valuePropName="checked"
				>
					<Switch />
				</Form.Item>
			</Form>
			{application && (
				<Flex
					vertical
					gap={12}
				>
					<Typography.Text>
						Issuer:{' '}
						<Typography.Text copyable>{application.issuer}</Typography.Text>
					</Typography.Text>
					<Typography.Text>
						Discovery:{' '}
						<Typography.Text copyable>
							{application.discoveryUrl}
						</Typography.Text>
					</Typography.Text>
					<Typography.Text type="secondary">
						Ask for the <Typography.Text code>groups</Typography.Text> scope to
						receive the administrator&apos;s teams.
					</Typography.Text>
					<Flex gap={8}>
						{application.hasSecret && (
							<Button onClick={() => void onRotate(application)}>
								Rotate secret
							</Button>
						)}
						<Button
							danger
							onClick={() => void onDelete(application)}
						>
							Delete
						</Button>
					</Flex>
				</Flex>
			)}
		</Drawer>
	);
}
