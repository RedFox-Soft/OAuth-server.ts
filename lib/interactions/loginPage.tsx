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
	buildUIFederationStartPath,
	buildUIPath
} from './buildUIPath.js';
import { DEFAULT_LOGO } from './logo.js';
import { knownProvider } from '../consts/known_providers.js';
import { providerMark } from './providerMark.js';
import { LanguageSwitch, type SwitcherProps } from './languageSwitch.js';
import { foxVar } from '../html/theme/palette.js';
import { useLanguage } from '../i18n/context.js';
import { Message, text } from '../i18n/message.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';

export function LoginPage({
	uid,
	errorMessage,
	notice,
	passwordLogin = true,
	registrationOpen = true,
	passwordReset = true,
	verificationResend = false,
	providers = [],
	logoSrc = DEFAULT_LOGO,
	embedded = false,
	switcher
}: {
	uid: string;
	errorMessage?: string;
	notice?: string;
	/* Defaulted so the component renders the password page for any caller that says nothing. */
	passwordLogin?: boolean;
	registrationOpen?: boolean;
	passwordReset?: boolean;
	verificationResend?: boolean;
	providers?: { id: string; displayName: string; brand?: string }[];
	/*
	 * The logo's versioned address, worked out by the server and handed over in the props. Computing it here
	 * cannot work: the version is the file's build time, read from disk, which a browser has no way to read —
	 * so the browser computed a different address and every hydration logged a mismatch.
	 */
	logoSrc?: string;
	/*
	 * Drawn inside the console's Sign-in tab as its preview (specs/091) rather than as a whole page: the same
	 * component, so the preview shows whatever this page shows, but sized to its content instead of the window.
	 */
	embedded?: boolean;
	/* The language switch (specs/097), present only for a visitor with a language other than English. */
	switcher?: SwitcherProps;
}) {
	const T = SIGN_IN_TEXTS[useLanguage()];
	return (
		<Flex
			justify="center"
			style={{
				display: 'flex',
				...(embedded ? { padding: '32px 16px' } : { height: '100vh' }),
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
									border: `1px solid ${foxVar('notice-border')}`,
									backgroundColor: foxVar('notice-bg'),
									display: 'flex',
									alignItems: 'center',
									gap: '8px'
								}}
							>
								<span
									style={{ color: foxVar('notice-text'), fontSize: '14px' }}
								>
									<InfoCircleOutlined aria-hidden="true" />
								</span>
								<span
									style={{ color: foxVar('notice-text'), fontSize: '14px' }}
								>
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
					{/*
					 * Everything a password needs, and nothing when the bucket has none. The fields, the
					 * "remember me", the submit, the reset link and the registration link all go together:
					 * each one leads somewhere that answers 403 on a federated-only bucket, so leaving any of
					 * them would be an invitation to a dead end. The two links also follow their own doors:
					 * a bucket can keep a password and still refuse registration or self-service reset.
					 */}
					{passwordLogin && (
						<>
							<Form.Item
								name="username"
								rules={[{ required: true, message: T.login.usernameRequired }]}
							>
								<Input
									name="username"
									prefix={<UserOutlined aria-hidden="true" />}
									placeholder={T.login.usernamePlaceholder}
								/>
							</Form.Item>
							<Form.Item
								name="password"
								rules={[{ required: true, message: T.login.passwordRequired }]}
							>
								<Input
									name="password"
									prefix={<LockOutlined aria-hidden="true" />}
									type="password"
									placeholder={T.login.passwordPlaceholder}
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
										<Checkbox name="remember">{T.login.remember}</Checkbox>
									</Form.Item>
									{passwordReset && (
										<a href={buildUIForgotPasswordPath(uid)}>
											{T.login.forgotPassword}
										</a>
									)}
								</Flex>
							</Form.Item>

							<Form.Item>
								<Button
									block
									type="primary"
									htmlType="submit"
								>
									{T.login.submit}
								</Button>
								{registrationOpen && (
									<>
										<Message
											t={T.login.registerPrompt}
											values={{
												link: (
													<a href={buildUIRegistrationPath(uid)}>
														{T.login.register}
													</a>
												)
											}}
										/>
									</>
								)}
							</Form.Item>
						</>
					)}
				</Form>
				{/*
				 * A form of its own, outside the sign-in <Form>: it posts nothing, because the account it
				 * concerns is the one this sign-in already proved the password of, held on the server.
				 */}
				{verificationResend && (
					<form
						method="post"
						action={buildUIPath(uid, 'verification/resend')}
						style={{ textAlign: 'center', marginTop: -8, marginBottom: 16 }}
					>
						<Button
							type="link"
							htmlType="submit"
						>
							{T.login.resendLink}
						</Button>
					</form>
				)}
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
									color: foxVar('text-muted'),
									fontSize: '12px',
									textAlign: 'center'
								}}
							>
								{T.login.orContinueWith}
							</div>
						)}
						{providers.map((provider) => {
							const known = knownProvider(provider.brand ?? '');
							const mark = providerMark(provider.brand);
							/*
							 * A recognised provider's button follows that provider's own branding
							 * requirements, which are a condition of using its mark rather than a design
							 * preference. Google's light theme is #FFFFFF on a #747775 stroke with #1F1F1F
							 * text, and its dark theme #131314 on #8E918F with #E3E3E3 (the palette's
							 * `provider-*` roles, chosen by the device's scheme); 12px before the mark, 10px
							 * after it and 12px after the text, and the mark is never shown without the text.
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
													backgroundColor: foxVar('provider-bg'),
													border: `1px solid ${foxVar('provider-border')}`,
													borderRadius: '6px',
													color: foxVar('provider-text'),
													textDecoration: 'none'
												}
											: {
													display: 'block',
													padding: '8px 16px',
													border: `1px solid ${foxVar('field-border')}`,
													borderRadius: '6px',
													textAlign: 'center',
													color: foxVar('text'),
													textDecoration: 'none'
												}
									}
								>
									{mark}
									{text(T.login.signInWith, {
										provider: known ? known.displayName : provider.displayName
									})}
								</a>
							);
						})}
					</Flex>
				)}
				{switcher && <LanguageSwitch {...switcher} />}
			</Card>
		</Flex>
	);
}
