import { Form, Input, Button, Checkbox, Flex, Card } from 'antd';
import {
	UserOutlined,
	LockOutlined,
	ExclamationCircleOutlined,
	InfoCircleOutlined
} from '@ant-design/icons';
import {
	buildUILoginPath,
	buildUIRegistrationPath,
	buildUIForgotPasswordPath,
	buildUIFederationStartPath
} from './buildUIPath.js';
import { versionedAsset } from '../html/versionedAsset.js';
import { knownProvider } from '../consts/known_providers.js';
import { providerMark } from './providerMark.js';

export function LoginPage({
	uid,
	errorMessage,
	notice,
	passwordLogin = true,
	providers = []
}: {
	uid: string;
	errorMessage?: string;
	notice?: string;
	/* Defaulted so the component renders the password page for any caller that says nothing. */
	passwordLogin?: boolean;
	providers?: { id: string; displayName: string; brand?: string }[];
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
						src={versionedAsset('logo.svg')}
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
					{/*
					 * Informational, not a failure — different colours and a different icon from the error
					 * block below, so which of the two this is never depends on reading the text. The two
					 * are mutually exclusive by construction in loginServer.
					 */}
					{notice && (
						<Form.Item>
							<div
								style={{
									padding: '12px 16px',
									borderRadius: '6px',
									border: '1px solid #91caff',
									backgroundColor: '#e6f4ff',
									display: 'flex',
									alignItems: 'center',
									gap: '8px'
								}}
							>
								<span style={{ color: '#0958d9', fontSize: '14px' }}>
									<InfoCircleOutlined />
								</span>
								<span style={{ color: '#0958d9', fontSize: '14px' }}>
									{notice}
								</span>
							</div>
						</Form.Item>
					)}
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
					{/*
					 * Everything a password needs, and nothing when the bucket has none. The fields, the
					 * "remember me", the submit, the reset link and the registration link all go together:
					 * each one leads somewhere that answers 403 on a federated-only bucket, so leaving any of
					 * them would be an invitation to a dead end.
					 */}
					{passwordLogin && (
						<>
							<Form.Item
								name="username"
								rules={[
									{ required: true, message: 'Please input your Username!' }
								]}
							>
								<Input
									name="username"
									prefix={<UserOutlined />}
									placeholder="Username"
								/>
							</Form.Item>
							<Form.Item
								name="password"
								rules={[
									{ required: true, message: 'Please input your Password!' }
								]}
							>
								<Input
									name="password"
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
										<Checkbox name="remember">Remember me</Checkbox>
									</Form.Item>
									<a href={buildUIForgotPasswordPath(uid)}>Forgot password</a>
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
						</>
					)}
				</Form>
				{/*
				 * Plain anchors, not buttons with handlers: leg one of the flow is a navigation, so this adds
				 * no script and no inline handler and the page's derived content security policy is unchanged.
				 * Outside the <Form> because submitting the form is not what these do.
				 */}
				{providers.length > 0 && (
					<Flex
						vertical
						gap={8}
					>
						{passwordLogin && (
							<div
								style={{
									color: '#8c8c8c',
									fontSize: '12px',
									textAlign: 'center'
								}}
							>
								or continue with
							</div>
						)}
						{providers.map((provider) => {
							const known = knownProvider(provider.brand ?? '');
							const mark = providerMark(provider.brand);
							/*
							 * A recognised provider's button follows that provider's own branding
							 * requirements, which are a condition of using its mark rather than a design
							 * preference. Google's light theme is #FFFFFF on a #747775 stroke with #1F1F1F
							 * text, 12px before the mark, 10px after it and 12px after the text, and the
							 * mark is never shown without the text.
							 *
							 * The wording comes from the catalogue, not from `displayName`: an administrator
							 * may rename a provider to anything, and a branded button whose text an operator
							 * can edit stops complying the first time somebody does.
							 */
							return (
								<a
									key={provider.id}
									href={buildUIFederationStartPath(uid, provider.id)}
									style={
										known
											? {
													display: 'flex',
													alignItems: 'center',
													justifyContent: 'center',
													gap: '10px',
													height: '40px',
													padding: '0 12px',
													backgroundColor: '#FFFFFF',
													border: '1px solid #747775',
													borderRadius: '6px',
													color: '#1F1F1F',
													textDecoration: 'none'
												}
											: {
													display: 'block',
													padding: '8px 16px',
													border: '1px solid #d9d9d9',
													borderRadius: '6px',
													textAlign: 'center',
													color: '#1f1f1f',
													textDecoration: 'none'
												}
									}
								>
									{mark}
									{known
										? known.buttonText
										: `Sign in with ${provider.displayName}`}
								</a>
							);
						})}
					</Flex>
				)}
			</Card>
		</Flex>
	);
}
