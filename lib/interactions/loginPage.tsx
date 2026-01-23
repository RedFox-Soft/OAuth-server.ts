import { Form, Input, Button, Checkbox, Flex, Card } from 'antd';
import {
	UserOutlined,
	LockOutlined,
	GoogleOutlined,
	ExclamationCircleOutlined
} from '@ant-design/icons';
import { buildUILoginPath, buildUIRegistrationPath } from './buildUIPath.js';

export function LoginPage({
	uid,
	errorMessage
}: {
	uid: string;
	errorMessage?: string;
}) {
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
				</div>
				<Form
					name="login"
					initialValues={{ remember: true }}
					method="post"
					action={buildUILoginPath(uid)}
					onFinish={() => {
						document.forms.namedItem('login')?.submit();
					}}
				>
					{errorMessage && (
						<Form.Item>
							<div
								style={{
									padding: '12px 16px',
									borderRadius: '6px',
									border: '1px solid #ffccc7',
									backgroundColor: '#fff2f0',
									display: 'flex',
									alignItems: 'center',
									gap: '8px'
								}}
							>
								<span style={{ color: '#ff4d4f', fontSize: '14px' }}>
									<ExclamationCircleOutlined />
								</span>
								<span style={{ color: '#ff4d4f', fontSize: '14px' }}>
									{errorMessage}
								</span>
							</div>
						</Form.Item>
					)}
					<Form.Item
						name="username"
						rules={[{ required: true, message: 'Please input your Username!' }]}
					>
						<Input
							name="username"
							prefix={<UserOutlined />}
							placeholder="Username"
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
					<Form.Item>
						<Button
							block
							icon={<GoogleOutlined />}
						>
							Sign in with Google
						</Button>
					</Form.Item>
					<Form.Item>
						<Flex
							justify="space-between"
							align="center"
						>
							<Form.Item
								name="remember"
								valuePropName="checked"
								noStyle
							>
								<Checkbox name="remember">Remember me</Checkbox>
							</Form.Item>
							<a href="">Forgot password</a>
						</Flex>
					</Form.Item>

					<Form.Item>
						<Button
							block
							type="primary"
							htmlType="submit"
						>
							Log in
						</Button>
						or <a href={buildUIRegistrationPath(uid)}>Register now!</a>
					</Form.Item>
				</Form>
			</Card>
		</Flex>
	);
}
