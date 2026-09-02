import { useEffect, useState } from 'react';
import {
	Button,
	Card,
	Form,
	Input,
	InputNumber,
	Switch,
	Tag,
	message
} from 'antd';

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

	async function load() {
		setLoading(true);
		try {
			const res = await fetch('/admin/api/settings/smtp');
			if (res.ok) form.setFieldsValue((await res.json()) as SmtpView);
		} finally {
			setLoading(false);
		}
	}
	useEffect(() => {
		load();
	}, []);

	async function save(values: SmtpView) {
		setSaving(true);
		try {
			const res = await fetch('/admin/api/settings/smtp', {
				method: 'PUT',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(values)
			});
			const body = (await res.json().catch(() => null)) as
				(SmtpView & { message?: string }) | null;
			if (!res.ok) {
				message.error(body?.message || 'failed to save SMTP settings');
				return;
			}
			if (body) form.setFieldsValue(body);
			message.success('SMTP settings saved');
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
						onClick={() => form.submit()}
					>
						Save
					</Button>
				</span>
			}
		>
			<Form<SmtpView>
				form={form}
				layout="vertical"
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
