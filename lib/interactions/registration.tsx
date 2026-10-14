import {
	LockOutlined,
	MailOutlined,
	ExclamationCircleOutlined
} from '@ant-design/icons';
import { Button, Card, Flex, Form, Input } from 'antd';
import { buildUILoginPath, buildUIRegistrationPath } from './buildUIPath.js';
import { DEFAULT_LOGO } from './logo.js';
import { foxVar } from '../html/theme/palette.js';
import { LanguageSwitch, type SwitcherProps } from './languageSwitch.js';
import { useLanguage } from '../i18n/context.js';
import { Message } from '../i18n/message.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';

export function RegistrationPage({
	uid,
	errorMessage,
	email,
	logoSrc = DEFAULT_LOGO,
	switcher
}: {
	uid: string;
	errorMessage?: string;
	email?: string;
	/* The logo's versioned address, from the server: see LoginPage. */
	logoSrc?: string;
	switcher?: SwitcherProps;
}) {
	const T = SIGN_IN_TEXTS[useLanguage()];
	return (
		<Flex
			justify="center"
			style={{
				display: 'flex',
				height: '100vh',
				alignItems: 'center',
				backgroundColor: foxVar('page')
			}}
		>
			<Card
				style={{
					width: 400,
					padding: 24,
					borderRadius: 12,
					boxShadow: `0 2px 8px ${foxVar('shadow')}`
				}}
			>
				<div style={{ textAlign: 'center', marginBottom: 24 }}>
					<img
						src={logoSrc}
						alt={T.logoAlt}
						style={{ width: 120 }}
					/>
					<h2>{T.registration.heading}</h2>
				</div>
				<Form
					name="registration"
					method="post"
					action={buildUIRegistrationPath(uid)}
					// The address the user just typed comes back with the page; the two passwords never do.
					initialValues={email ? { email } : undefined}
					onFinish={() => {
						document.forms.namedItem('registration')?.submit();
					}}
				>
					{errorMessage && (
						<Form.Item>
							<div
								style={{
									padding: '12px 16px',
									borderRadius: '6px',
									border: `1px solid ${foxVar('danger-border')}`,
									backgroundColor: foxVar('danger-bg'),
									display: 'flex',
									alignItems: 'center',
									gap: '8px'
								}}
							>
								<span
									style={{ color: foxVar('danger-text'), fontSize: '14px' }}
								>
									<ExclamationCircleOutlined aria-hidden="true" />
								</span>
								<span
									style={{ color: foxVar('danger-text'), fontSize: '14px' }}
								>
									{errorMessage}
								</span>
							</div>
						</Form.Item>
					)}
					<Form.Item
						name="email"
						rules={[
							{ required: true, message: T.registration.emailRequired },
							{ type: 'email', message: T.registration.emailInvalid }
						]}
					>
						<Input
							name="email"
							prefix={<MailOutlined aria-hidden="true" />}
							placeholder={T.registration.emailPlaceholder}
						/>
					</Form.Item>
					<Form.Item
						name="password"
						rules={[
							{ required: true, message: T.registration.passwordRequired }
						]}
					>
						<Input
							name="password"
							prefix={<LockOutlined aria-hidden="true" />}
							type="password"
							placeholder={T.registration.passwordPlaceholder}
						/>
					</Form.Item>
					<Form.Item
						name="confirmPassword"
						dependencies={['password']}
						rules={[
							{ required: true, message: T.registration.confirmRequired },
							({ getFieldValue }) => ({
								validator(_, value) {
									if (!value || getFieldValue('password') === value) {
										return Promise.resolve();
									}
									return Promise.reject(
										new Error(T.registration.confirmMismatch)
									);
								}
							})
						]}
					>
						<Input
							name="confirmPassword"
							prefix={<LockOutlined aria-hidden="true" />}
							type="password"
							placeholder={T.registration.confirmPlaceholder}
						/>
					</Form.Item>

					<Form.Item>
						<Button
							block
							type="primary"
							htmlType="submit"
						>
							{T.registration.submit}
						</Button>
						<Message
							t={T.registration.loginPrompt}
							values={{
								link: <a href={buildUILoginPath(uid)}>{T.registration.login}</a>
							}}
						/>
					</Form.Item>
				</Form>
				{switcher && <LanguageSwitch {...switcher} />}
			</Card>
		</Flex>
	);
}
