import { LockOutlined, MailOutlined } from '@ant-design/icons';
import { Button, Card, Flex, Form, Input } from 'antd';
import { buildUILoginPath, buildUIRegistrationPath } from './buildUIPath.js';

export function RegistrationPage({ uid }: { uid: string }) {
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
			<Card
				style={{
					width: 400,
					padding: 24,
					borderRadius: 12,
					boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)'
				}}
			>
				<div style={{ textAlign: 'center', marginBottom: 24 }}>
					<img
						src="/public/logo.svg"
						alt="Logo"
						style={{ width: 120 }}
					/>
					<h2>Create Account</h2>
				</div>
				<Form
					name="registration"
					method="post"
					action={buildUIRegistrationPath(uid)}
					onFinish={() => {
						document.forms.namedItem('registration')?.submit();
					}}
				>
					<Form.Item
						name="email"
						rules={[
							{ required: true, message: 'Please input your Email!' },
							{ type: 'email', message: 'Please enter a valid Email!' }
						]}
					>
						<Input
							name="email"
							prefix={<MailOutlined />}
							placeholder="Email"
						/>
					</Form.Item>
					<Form.Item
						name="password"
						rules={[{ required: true, message: 'Please input your Password!' }]}
					>
						<Input
							name="password"
							prefix={<LockOutlined />}
							type="password"
							placeholder="Password"
						/>
					</Form.Item>
					<Form.Item
						name="confirmPassword"
						dependencies={['password']}
						rules={[
							{ required: true, message: 'Please confirm your Password!' },
							({ getFieldValue }) => ({
								validator(_, value) {
									if (!value || getFieldValue('password') === value) {
										return Promise.resolve();
									}
									return Promise.reject(new Error('Passwords do not match!'));
								}
							})
						]}
					>
						<Input
							name="confirmPassword"
							prefix={<LockOutlined />}
							type="password"
							placeholder="Confirm Password"
						/>
					</Form.Item>

					<Form.Item>
						<Button
							block
							type="primary"
							htmlType="submit"
						>
							Register
						</Button>
						or <a href={buildUILoginPath(uid)}>Already have an account?</a>
					</Form.Item>
				</Form>
			</Card>
		</Flex>
	);
}
