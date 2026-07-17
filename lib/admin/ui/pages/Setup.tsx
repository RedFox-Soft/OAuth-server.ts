import { useState } from 'react';
import { Form, Input, Button, Card, Flex, Typography, Alert } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';

interface SetupValues {
	email: string;
	password: string;
}

export function Setup() {
	const [submitting, setSubmitting] = useState(false);
	const [error, setError] = useState<string | null>(null);

	async function onFinish(values: SetupValues) {
		setSubmitting(true);
		setError(null);
		try {
			const res = await fetch('/admin/api/setup', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(values)
			});
			if (!res.ok) {
				const body = (await res.json().catch(() => null)) as {
					message?: string;
				} | null;
				setError(body?.message || 'setup failed');
				setSubmitting(false);
				return;
			}
			window.location.href = '/admin';
		} catch {
			setError('setup failed');
			setSubmitting(false);
		}
	}

	return (
		<Flex
			justify="center"
			style={{
				display: 'flex',
				height: '100vh',
				alignItems: 'center',
				backgroundColor: '#f0f2f5'
			}}
		>
			<Card style={{ width: 420, padding: 24, borderRadius: 12 }}>
				<Typography.Title
					level={3}
					style={{ textAlign: 'center' }}
				>
					Create the first super admin
				</Typography.Title>
				{error && (
					<Form.Item>
						<Alert
							type="error"
							showIcon
							message={error}
						/>
					</Form.Item>
				)}
				<Form<SetupValues>
					name="setup"
					layout="vertical"
					onFinish={onFinish}
				>
					<Form.Item
						name="email"
						label="Email"
						rules={[{ required: true, type: 'email' }]}
					>
						<Input
							prefix={<UserOutlined />}
							placeholder="you@example.com"
						/>
					</Form.Item>
					<Form.Item
						name="password"
						label="Password"
						rules={[{ required: true, min: 12 }]}
					>
						<Input.Password
							prefix={<LockOutlined />}
							placeholder="at least 12 characters"
						/>
					</Form.Item>
					<Form.Item>
						<Button
							block
							type="primary"
							htmlType="submit"
							loading={submitting}
						>
							Create super admin
						</Button>
					</Form.Item>
				</Form>
			</Card>
		</Flex>
	);
}
