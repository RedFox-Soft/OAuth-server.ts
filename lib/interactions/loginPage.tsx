import { Form, Input, Button, Checkbox, Flex, Card } from 'antd';
import { UserOutlined, LockOutlined } from '@ant-design/icons';
import React from 'react';
import { buildUILoginPath } from './buildUIPath.js';

export function LoginPage({ uid }: { uid: string }) {
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
				>
					<Form.Item
						name="username"
						rules={[{ required: true, message: 'Please input your Username!' }]}
					>
						<Input
							prefix={<UserOutlined />}
							placeholder="Username"
						/>
					</Form.Item>
					<Form.Item
						name="password"
						rules={[{ required: true, message: 'Please input your Password!' }]}
					>
						<Input
							prefix={<LockOutlined />}
							type="password"
							placeholder="Password"
						/>
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
								<Checkbox>Remember me</Checkbox>
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
						or <a href="">Register now!</a>
					</Form.Item>
				</Form>
			</Card>
		</Flex>
	);
}
