import { useState } from 'react';
import {
	Alert,
	Button,
	Card,
	Flex,
	Form,
	Input,
	Result,
	Typography
} from 'antd';
import { LockOutlined } from '@ant-design/icons';
import { request } from '../frame/request.js';
import { useRoute } from '../frame/router.js';

/*
 * Where the link in an invitation email lands. Public: the invitee usually has no account yet, and the
 * token in the address is the only credential (lib/admin/groups/accept.ts).
 *
 * The page cannot tell whether the invitee already has an account — saying so would confirm which
 * addresses are administrators — so the password is asked for always and used only when the account is
 * new. An existing administrator leaves it empty and simply joins the group.
 */
export function AcceptInvitation() {
	const { query } = useRoute();
	const token = query.get('token') ?? '';
	const [submitting, setSubmitting] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [accepted, setAccepted] = useState(false);

	async function onFinish(values: { password?: string }) {
		setSubmitting(true);
		setError(null);
		const result = await request('POST', '/admin/api/invitations/accept', {
			token,
			...(values.password ? { password: values.password } : {})
		});
		setSubmitting(false);
		if (result.ok) setAccepted(true);
		else setError(result.error.message);
	}

	return (
		<Flex
			justify="center"
			align="center"
			style={{ minHeight: '100vh', backgroundColor: '#f0f2f5', padding: 16 }}
		>
			<Card style={{ width: 420, maxWidth: '100%', borderRadius: 12 }}>
				{!token ? (
					<Result
						status="warning"
						title="This invitation link is incomplete"
						subTitle="Open the link from the invitation email again, or ask the group owner to send a new one."
					/>
				) : accepted ? (
					<Result
						status="success"
						title="You have joined the group"
						extra={
							<Button
								type="primary"
								href="/admin/login"
							>
								Sign in
							</Button>
						}
					/>
				) : (
					<>
						<Typography.Title level={3}>Accept the invitation</Typography.Title>
						<Typography.Paragraph type="secondary">
							If you already administer this server, leave the password empty:
							you join the group with the account you have. Otherwise choose a
							password for your new administrator account.
						</Typography.Paragraph>
						{error && (
							<Alert
								type="error"
								showIcon
								title={error}
								style={{ marginBottom: 16 }}
							/>
						)}
						<Form
							layout="vertical"
							onFinish={(values: { password?: string }) =>
								void onFinish(values)
							}
						>
							<Form.Item
								name="password"
								label="Password for a new account"
								rules={[
									{ min: 8, message: 'At least 8 characters' },
									{ max: 200, message: 'At most 200 characters' }
								]}
							>
								<Input.Password
									prefix={<LockOutlined />}
									autoComplete="new-password"
								/>
							</Form.Item>
							<Button
								type="primary"
								htmlType="submit"
								loading={submitting}
								block
							>
								Accept invitation
							</Button>
						</Form>
					</>
				)}
			</Card>
		</Flex>
	);
}
