import { useEffect, useState, useSyncExternalStore } from 'react';
import { Form, Input, Button, Checkbox, Flex, Card, Divider } from 'antd';
import {
	MailOutlined,
	LockOutlined,
	ExclamationCircleOutlined,
	InfoCircleOutlined,
	KeyOutlined
} from '@ant-design/icons';
import {
	browserSupportsWebAuthn,
	browserSupportsWebAuthnAutofill,
	startAuthentication,
	type AuthenticationResponseJSON,
	type PublicKeyCredentialRequestOptionsJSON
} from '@simplewebauthn/browser';
import {
	buildUILoginPath,
	buildUIRegistrationPath,
	buildUIForgotPasswordPath,
	buildUIFederationStartPath,
	buildUIPath
} from './buildUIPath.js';
import { DEFAULT_LOGO } from './logo.js';
import { SignInMasthead, type SignInFace } from './signInMasthead.js';
import { knownProvider } from '../consts/known_providers.js';
import { genericMark, providerMark } from './providerMark.js';
import { LanguageSwitch, type SwitcherProps } from './languageSwitch.js';
import { foxVar } from '../html/theme/palette.js';
import { useLanguage } from '../i18n/context.js';
import { Message, text } from '../i18n/message.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';
import type { OfferedProvider } from './signInOptions.js';

/*
 * The passkey offer a render of the page carries (specs/139 contracts/sign-in.md): the request options with the
 * challenge the server wrote onto this interaction, and whether the page's "Remember me" decides how long the session
 * lasts. The console's preview passes no options: it draws the button and can never start a prompt (FR-012).
 */
export interface PasskeyOnPage {
	options?: PublicKeyCredentialRequestOptionsJSON;
	remember: boolean;
}

/*
 * The password form's "Remember me" checkbox, which the passkey's post copies. antd's `<Form name="login">` renders
 * `id="login"`, not a `name` attribute: a `form[name="login"]` selector matched nothing in a browser, so an unticked box
 * was never copied and every passkey sign-in was remembered (found in the browser walk, specs/139 T058).
 */
export const REMEMBER_TICK = 'form#login input[name="remember"]';

/*
 * Hands the browser's answer to the passkey door the way the password form is sent: a native post of the hidden form,
 * so the server answers with a redirect or a page exactly as it does to a password. With a "Remember me" on the page
 * its tick is sent along; without one the sign-in is remembered, as a provider sign-in is.
 */
function sendPasskey(
	answer: AuthenticationResponseJSON,
	rememberAsked: boolean
): void {
	const form = document.forms.namedItem('passkey');
	const credential = form?.elements.namedItem('credential');
	const remember = form?.elements.namedItem('remember');
	if (
		!form ||
		!(credential instanceof HTMLInputElement) ||
		!(remember instanceof HTMLInputElement)
	)
		return;
	credential.value = JSON.stringify(answer);
	const ticked =
		document.querySelector<HTMLInputElement>(REMEMBER_TICK)?.checked;
	// A disabled field is not sent: an absent `remember` is the server's "don't remember".
	remember.disabled = rememberAsked && ticked === false;
	form.submit();
}

/* Whether the browser can use passkeys does not change while the page is open. */
function neverChanges(): () => void {
	return () => {};
}

function notOnTheServer(): boolean {
	return false;
}

export function LoginPage({
	uid,
	errorMessage,
	notice,
	passwordLogin = true,
	registrationOpen = true,
	passwordReset = true,
	verificationResend = false,
	providers = [],
	providersOpen = false,
	logoSrc = DEFAULT_LOGO,
	embedded = false,
	switcher,
	face,
	listRefusal,
	passkey
}: {
	uid: string;
	/* Signing in with a passkey, offered in every form of this page where the project accepts passkeys (specs/139). */
	passkey?: PasskeyOnPage;
	errorMessage?: string;
	notice?: string;
	/*
	 * This network's address is on FoxTrust's list and has just failed passwords here (specs/125): the refusal takes
	 * the password form's place, and the caller passes `passwordLogin: false` so the form and its links go with it
	 * while other ways to sign in stay. `line` is the person's own support line; `disputeUrl` comes from the list.
	 */
	listRefusal?: { line: string; disputeUrl: string | null };
	/* Defaulted so the component renders the password page for any caller that says nothing. */
	passwordLogin?: boolean;
	registrationOpen?: boolean;
	passwordReset?: boolean;
	verificationResend?: boolean;
	providers?: OfferedProvider[];
	/*
	 * Whether "More sign-in options" starts open: decided by the server (after a cancelled provider sign-in) and
	 * handed over in the props, so the first render and the hydrated one agree.
	 */
	providersOpen?: boolean;
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
	/* Where this sign-in leads: the project, and the application when its project stands behind it. */
	face: SignInFace;
}) {
	const T = SIGN_IN_TEXTS[useLanguage()];
	const offer = passkey?.options;
	const rememberAsked = passkey?.remember === true;
	/*
	 * Disabled on the server and in the render that hydrates its markup, so the two match (the server's answer is
	 * "no"); enabled once the browser has said it can use passkeys at all (research R8).
	 */
	const webAuthn = useSyncExternalStore(
		neverChanges,
		browserSupportsWebAuthn,
		notOnTheServer
	);
	const passkeyReady = !embedded && offer !== undefined && webAuthn;
	const [passkeyCancelled, setPasskeyCancelled] = useState(false);
	useEffect(() => {
		if (!passkeyReady) return;
		let current = true;
		/*
		 * The browser's own suggestions on the email field (FR-011), where it can show them: the request waits for the
		 * person to pick a passkey there. The button starts a request of its own, which ends this one first.
		 */
		void browserSupportsWebAuthnAutofill().then((autofill) => {
			if (!autofill || !current) return;
			startAuthentication({ optionsJSON: offer, useBrowserAutofill: true })
				.then((answer) => {
					sendPasskey(answer, rememberAsked);
				})
				.catch(() => {
					/* Ended by the button, or never chosen: there is nothing to tell the person. */
				});
		});
		return () => {
			current = false;
		};
	}, [passkeyReady, offer, rememberAsked]);
	const startPasskey = () => {
		if (!passkeyReady) return;
		setPasskeyCancelled(false);
		startAuthentication({ optionsJSON: offer })
			.then((answer) => {
				sendPasskey(answer, rememberAsked);
			})
			.catch(() => {
				setPasskeyCancelled(true);
			});
	};
	/*
	 * The button leads the "or" block in the providers' own frame (research R8), with the line scripts-off readers see
	 * and the line after a closed prompt. In the console's preview it is drawn as it looks and does nothing.
	 */
	const passkeyButton = passkey && (
		<Flex
			vertical
			gap={4}
		>
			<button
				type="button"
				disabled={!embedded && !passkeyReady}
				onClick={startPasskey}
				style={{
					display: 'flex',
					alignItems: 'center',
					justifyContent: 'center',
					gap: '10px',
					width: '100%',
					minHeight: '44px',
					padding: '10px 12px',
					backgroundColor: foxVar('provider-bg'),
					border: `1px solid ${foxVar('provider-border')}`,
					borderRadius: '6px',
					color: foxVar('provider-text'),
					font: 'inherit',
					cursor: 'pointer'
				}}
			>
				<span style={{ display: 'inline-flex', flexShrink: 0 }}>
					<KeyOutlined aria-hidden="true" />
				</span>
				<span>{T.login.passkey}</span>
			</button>
			<noscript>
				<span style={{ color: foxVar('text-muted'), fontSize: '14px' }}>
					{T.login.passkeyNoScript}
				</span>
			</noscript>
			{passkeyCancelled && (
				<span
					role="status"
					style={{ color: foxVar('text-muted'), fontSize: '14px' }}
				>
					{T.login.passkeyCancelled}
				</span>
			)}
		</Flex>
	);
	/*
	 * Where the page has no password form (password sign-in off, or the attacker list's refusal): an email field of
	 * its own, which the browser hangs its passkey suggestions on and which is never sent, then the button.
	 */
	const passkeyBlock = passkey && (
		<Flex
			vertical
			gap={8}
			style={{ marginBottom: 24 }}
		>
			<Input
				prefix={<MailOutlined aria-hidden="true" />}
				placeholder={T.login.emailPlaceholder}
				aria-label={T.login.emailPlaceholder}
				autoComplete="username webauthn"
				inputMode="email"
			/>
			{passkeyButton}
		</Flex>
	);
	const link = (provider: OfferedProvider) => (
		<ProviderLink
			key={provider.id}
			uid={uid}
			provider={provider}
			wording={T.login.signInWith}
		/>
	);
	const shown = providers.filter((provider) => !provider.folded);
	const folded = providers.filter((provider) => provider.folded);
	/*
	 * Plain anchors and a native disclosure, not buttons with handlers: leg one of the flow is a navigation and the
	 * fold opens without a script, so the page works with scripts off and its derived content security policy is
	 * unchanged. Outside the <Form> because submitting the form is not what these do.
	 *
	 * Which providers are folded is decided by the server (signInOptions.ts), never here: this component renders
	 * twice from one props payload, and the console's preview draws it too. `open` is set once from a prop the
	 * server chose; afterwards the browser owns it, and nothing re-renders this with another value.
	 */
	const providerBlock = providers.length > 0 && (
		<Flex
			vertical
			gap={8}
			style={passwordLogin ? undefined : { marginBottom: 24 }}
		>
			{shown.map(link)}
			{folded.length > 0 && (
				<details open={providersOpen}>
					<summary
						style={{
							cursor: 'pointer',
							textAlign: 'center',
							color: foxVar('text-muted'),
							fontSize: '14px',
							margin: '4px 0'
						}}
					>
						{T.login.moreProviders}
					</summary>
					<Flex
						vertical
						gap={8}
						style={{ marginTop: 8 }}
					>
						{folded.map(link)}
					</Flex>
				</details>
			)}
		</Flex>
	);
	return (
		<Flex
			justify="center"
			style={{
				display: 'flex',
				/*
				 * `minHeight`, not `height`: a card taller than the window, centred in a box exactly the window's
				 * height, overflows both ends, and the top end — the logo, any notice — cannot be scrolled to.
				 */
				...(embedded
					? { padding: '32px 16px' }
					: { minHeight: '100vh', padding: 16 }),
				alignItems: 'center',
				backgroundColor: foxVar('page')
			}}
		>
			<Card
				/*
				 * Fluid up to 400 px: a fixed 400 scrolled a 320 px phone sideways. The card's own padding melts away
				 * below 368 px so the buttons keep about 240 px of width there; from 368 px up it is today's card.
				 */
				style={{
					width: '100%',
					maxWidth: 400,
					padding: embedded ? 24 : 'clamp(0px, calc(100vw - 344px), 24px)',
					borderRadius: 12,
					boxShadow: `0 2px 8px ${foxVar('shadow')}`
				}}
			>
				<SignInMasthead
					face={face}
					logoSrc={logoSrc}
					heading={
						face.app ? (
							<Message
								t={T.headings.loginToApp}
								values={{ app: face.app.name }}
							/>
						) : (
							<Message
								t={T.headings.login}
								values={{ service: face.service }}
							/>
						)
					}
				/>
				{/*
				 * Above the form rather than inside it, so a notice still leads a page that has no password form
				 * and opens with provider buttons (specs/105).
				 *
				 * Informational, not a failure — different colours and a different icon from the error
				 * block below, so which of the two this is never depends on reading the text. The two
				 * are mutually exclusive by construction in loginServer.
				 */}
				{notice && (
					<div style={{ marginBottom: 24 }}>
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
							<span style={{ color: foxVar('notice-text'), fontSize: '14px' }}>
								<InfoCircleOutlined aria-hidden="true" />
							</span>
							<span style={{ color: foxVar('notice-text'), fontSize: '14px' }}>
								{notice}
							</span>
						</div>
					</div>
				)}
				{errorMessage && (
					<div style={{ marginBottom: 24 }}>
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
							<span style={{ color: foxVar('danger-text'), fontSize: '14px' }}>
								<ExclamationCircleOutlined aria-hidden="true" />
							</span>
							<span style={{ color: foxVar('danger-text'), fontSize: '14px' }}>
								{errorMessage}
							</span>
						</div>
					</div>
				)}
				{listRefusal && (
					<div
						role="alert"
						style={{
							marginBottom: 24,
							padding: '12px 16px',
							borderRadius: '6px',
							border: `1px solid ${foxVar('warn-border')}`,
							backgroundColor: foxVar('warn-bg'),
							color: foxVar('text'),
							fontSize: '14px'
						}}
					>
						<p style={{ margin: '0 0 8px', fontWeight: 600 }}>
							<ExclamationCircleOutlined
								aria-hidden="true"
								style={{ color: foxVar('warn-icon'), marginRight: 8 }}
							/>
							{T.login.listRefusal.title}
						</p>
						<p style={{ margin: '0 0 8px' }}>{T.login.listRefusal.happened}</p>
						<p style={{ margin: '0 0 8px' }}>{T.login.listRefusal.whatNow}</p>
						<p style={{ margin: '0 0 4px' }}>{T.login.listRefusal.support}</p>
						<code
							style={{
								display: 'block',
								overflowWrap: 'anywhere',
								margin: '0 0 8px',
								padding: '4px 8px',
								borderRadius: 4,
								border: `1px solid ${foxVar('code-border')}`,
								backgroundColor: foxVar('box')
							}}
						>
							{listRefusal.line}
						</code>
						{listRefusal.disputeUrl && (
							<a
								href={listRefusal.disputeUrl}
								rel="noopener noreferrer"
								style={{ color: foxVar('link') }}
							>
								{T.login.listRefusal.dispute}
							</a>
						)}
					</div>
				)}
				{!passwordLogin && passkeyBlock}
				{!passwordLogin && providerBlock}
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
								rules={[{ required: true, message: T.login.emailRequired }]}
							>
								<Input
									name="username"
									prefix={<MailOutlined aria-hidden="true" />}
									placeholder={T.login.emailPlaceholder}
									autoComplete={passkey ? 'username webauthn' : 'username'}
									inputMode="email"
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
									autoComplete="current-password"
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
				{passwordLogin && (providers.length > 0 || passkey) && (
					<>
						<Divider plain>
							<span style={{ color: foxVar('text-muted') }}>
								{T.login.providersDivider}
							</span>
						</Divider>
						<Flex
							vertical
							gap={8}
						>
							{passkeyButton}
							{providerBlock}
						</Flex>
					</>
				)}
				{/*
				 * The passkey door's own form, posted by the script with the browser's answer: never typed into, and with
				 * no script nothing can fill it, so it renders nothing a person sees.
				 */}
				{passkey && (
					<form
						name="passkey"
						method="post"
						action={buildUIPath(uid, 'passkey')}
						hidden
					>
						<input
							type="hidden"
							name="credential"
						/>
						<input
							type="hidden"
							name="remember"
							value="on"
						/>
					</form>
				)}
				{switcher && <LanguageSwitch {...switcher} />}
			</Card>
		</Flex>
	);
}

/*
 * One provider's button, the same frame for every provider (specs/105). A recognised provider's button follows
 * that provider's own branding requirements, which are a condition of using its mark rather than a design
 * preference: Google's light theme is #FFFFFF on a #747775 stroke with #1F1F1F text, its dark theme #131314 on
 * #8E918F with #E3E3E3 (the palette's `provider-*` roles, chosen by the device's scheme), and the mark is never
 * shown without the text. A provider this server does not recognise gets the same frame and a neutral mark, so
 * it does not read as the lesser option; it used to be a lighter, shorter box with no mark.
 *
 * 44 px high at least — Apple's minimum, and no smaller than the Log in button, which Google and Apple require.
 * The text wraps rather than truncating: cutting a brand's wording short would break its rules.
 *
 * The wording comes from the catalogue, not from `displayName`: an administrator may rename a provider to
 * anything, and a branded button whose text an operator can edit stops complying the first time somebody does.
 * Two connections to one brand keep that wording and add the administrator's name beneath it, the only text
 * that tells them apart.
 */
function ProviderLink({
	uid,
	provider,
	wording
}: {
	uid: string;
	provider: OfferedProvider;
	wording: string;
}) {
	const known = knownProvider(provider.brand ?? '');
	const label = text(wording, {
		provider: known ? known.displayName : provider.displayName
	});
	return (
		<a
			href={buildUIFederationStartPath(uid, provider.id)}
			style={{
				display: 'flex',
				alignItems: 'center',
				justifyContent: 'center',
				gap: '10px',
				minHeight: '44px',
				padding: '10px 12px',
				backgroundColor: foxVar('provider-bg'),
				border: `1px solid ${foxVar('provider-border')}`,
				borderRadius: '6px',
				color: foxVar('provider-text'),
				textAlign: 'center',
				textDecoration: 'none'
			}}
		>
			<span style={{ display: 'inline-flex', flexShrink: 0 }}>
				{providerMark(provider.brand) ?? genericMark()}
			</span>
			{provider.subtitle === undefined ? (
				<span>{label}</span>
			) : (
				<span style={{ display: 'flex', flexDirection: 'column' }}>
					<span>{label}</span>
					<span
						style={{ fontSize: '12px', color: foxVar('provider-text-muted') }}
					>
						{provider.subtitle}
					</span>
				</span>
			)}
		</a>
	);
}
