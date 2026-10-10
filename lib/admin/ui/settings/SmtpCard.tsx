import { useCallback, useEffect, useState } from 'react';
import { Button, Card, Form, Input, InputNumber, Switch, Tag } from 'antd';
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
 */
export function SmtpCard() {
	const [form] = Form.useForm<SmtpView>();
	const [loading, setLoading] = useState(true);
	const [saving, setSaving] = useState(false);
	const [failed, setFailed] = useState<string | null>(null);
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
			feedback.done('SMTP settings saved.');
		} finally {
			setSaving(false);
		}
	}

	return (
		<Card
			title="Email (SMTP)"
			size="small"
			style={{ marginBottom: 16 }}
			loading={loading}
			extra={
				<span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
					<Tag color="green">applies immediately</Tag>
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
