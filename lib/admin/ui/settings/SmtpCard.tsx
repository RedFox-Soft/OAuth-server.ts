import { useCallback, useEffect, useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Form,
	Input,
	InputNumber,
	Switch,
	Tag,
	Tooltip
} from 'antd';
import { request } from '../frame/request.js';
import { useFeedback } from '../frame/feedback.js';
import { LoadFailed } from '../frame/states.js';

interface SmtpView {
	host: string;
	port: number;
	secure: boolean;
	username: string;
	password: string;
	fromName: string;
	fromEmail: string;
	configured: boolean;
}

/*
 * Runtime SMTP transport used for verification emails. Separate from the catalogued settings, and
 * the card says so: changes here take effect immediately, where everything the save bar covers waits
 * for a restart. That difference is the one thing about this page an operator most needs to know and
 * the page never used to state it — the restart warning only appeared after a save had happened.
 *
 * The password is write-only — the API returns a mask and accepts the mask back to mean "unchanged".
 *
 * The test sends to the signed-in administrator through the *saved* settings, so it is offered only while
 * the form holds nothing unsaved: testing values that are not what the server will use answers the wrong
 * question. Its outcome stays on the card rather than in a toast, because a refusal carries the mail
 * server's own reply, which is what the operator has to read and act on.
 */
export function SmtpCard() {
	const [form] = Form.useForm<SmtpView>();
	const [loading, setLoading] = useState(true);
	const [saving, setSaving] = useState(false);
	const [failed, setFailed] = useState<string | null>(null);
	const [configured, setConfigured] = useState(false);
	const [dirty, setDirty] = useState(false);
	const [testing, setTesting] = useState(false);
	const [tested, setTested] = useState<
		{ ok: true; to: string } | { ok: false; reason: string } | null
	>(null);
	const feedback = useFeedback();

	// Every state write follows an await: `loading` starts true, so the mount has nothing to set first.
	const load = useCallback(async () => {
		try {
			const result = await request<SmtpView>('GET', '/admin/api/settings/smtp');
			if (!result.ok) {
				setFailed(result.error.message);
				return;
			}
			setFailed(null);
			form.setFieldsValue(result.data);
			setConfigured(result.data.configured);
			setDirty(false);
		} finally {
			setLoading(false);
		}
	}, [form]);
	function reload() {
		setLoading(true);
		void load();
	}
	useEffect(() => {
		void load();
	}, [load]);

	async function save(values: SmtpView) {
		setSaving(true);
		try {
			const result = await request<SmtpView>(
				'PUT',
				'/admin/api/settings/smtp',
				values
			);
			if (!result.ok) {
				feedback.failed(result, form);
				return;
			}
			form.setFieldsValue(result.data);
			setConfigured(result.data.configured);
			setDirty(false);
			setTested(null);
			feedback.done('SMTP settings saved.');
		} finally {
			setSaving(false);
		}
	}

	async function sendTest() {
		setTesting(true);
		setTested(null);
		try {
			const result = await request<{ sent: true; to: string }>(
				'POST',
				'/admin/api/settings/smtp/test'
			);
			setTested(
				result.ok
					? { ok: true, to: result.data.to }
					: { ok: false, reason: result.error.message }
			);
		} finally {
			setTesting(false);
		}
	}

	const testBlocked = !configured
		? 'Save the mail settings first.'
		: dirty
			? 'Save your changes first: the test uses the saved settings.'
			: null;

	return (
		<Card
			title="Email (SMTP)"
			size="small"
			style={{ marginBottom: 16 }}
			loading={loading}
			extra={
				<span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
					<Tag color="green">applies immediately</Tag>
					<Tooltip title={testBlocked}>
						<Button
							loading={testing}
							disabled={failed !== null || testBlocked !== null}
							onClick={() => void sendTest()}
						>
							Send test email
						</Button>
					</Tooltip>
					<Button
						type="primary"
						loading={saving}
						disabled={failed !== null}
						onClick={() => form.submit()}
					>
						Save
					</Button>
				</span>
			}
		>
			{tested && (
				<Alert
					style={{ marginBottom: 16 }}
					showIcon
					closable={{ onClose: () => setTested(null) }}
					type={tested.ok ? 'success' : 'error'}
					title={
						tested.ok
							? `The mail server accepted a test message to ${tested.to}.`
							: 'The test message was not sent.'
					}
					description={
						tested.ok
							? 'Accepted is not yet delivered: if it does not arrive in a few minutes, look in spam and check the sender domain’s SPF, DKIM and DMARC records.'
							: tested.reason
					}
				/>
			)}
			{failed !== null && (
				<LoadFailed
					reason={failed}
					onRetry={reload}
				/>
			)}
			{/*
			 * Hidden rather than unmounted on a failed load: the form instance stays connected, and saving
			 * blank fields over a configuration that could not be read is not offered.
			 */}
			<Form<SmtpView>
				form={form}
				layout="vertical"
				scrollToFirstError
				hidden={failed !== null}
				onValuesChange={() => setDirty(true)}
				onFinish={save}
			>
				<Form.Item
					name="host"
					label="Host"
					rules={[{ required: true }]}
				>
					<Input placeholder="smtp.example.com" />
				</Form.Item>
				<Form.Item
					name="port"
					label="Port"
					rules={[{ required: true }]}
				>
					{/*
					 * `InputNumber`, not `<Input type="number">`: the latter is still a text input and
					 * submits "587" as a string, which the body schema refuses. See the note on `port` in
					 * lib/admin/settings/smtp/schema.ts.
					 */}
					<InputNumber
						min={1}
						max={65535}
						step={1}
						placeholder="587"
						style={{ width: '100%' }}
					/>
				</Form.Item>
				<Form.Item
					name="secure"
					label="Use TLS on connect"
					valuePropName="checked"
				>
					<Switch />
				</Form.Item>
				<Form.Item
					name="username"
					label="Username"
				>
					<Input autoComplete="off" />
				</Form.Item>
				<Form.Item
					name="password"
					label="Password"
					extra="Leave the masked value to keep the stored password."
				>
					<Input.Password autoComplete="new-password" />
				</Form.Item>
				<Form.Item
					name="fromName"
					label="Sender name"
				>
					<Input placeholder="Example" />
				</Form.Item>
				<Form.Item
					name="fromEmail"
					label="Sender email"
					rules={[{ required: true, type: 'email' }]}
				>
					<Input placeholder="no-reply@example.com" />
				</Form.Item>
			</Form>
		</Card>
	);
}
