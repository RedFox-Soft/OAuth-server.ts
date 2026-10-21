import {
	ExclamationCircleOutlined,
	SafetyCertificateOutlined
} from '@ant-design/icons';
import { Button, Card, Flex, Form, Input, QRCode, Typography } from 'antd';
import { buildUIPath } from './buildUIPath.js';
import { DEFAULT_LOGO } from './logo.js';
import { SignInMasthead, type SignInFace } from './signInMasthead.js';
import { foxVar } from '../html/theme/palette.js';
import { LanguageSwitch, type SwitcherProps } from './languageSwitch.js';
import { useLanguage } from '../i18n/context.js';
import { SIGN_IN_TEXTS } from '../i18n/texts/signIn/index.js';

/*
 * The second factor's one page, in two modes.
 *
 * One component rather than two because the enrolment step and the code step differ only in what sits
 * above the same six-digit field, and because `loginClient.tsx` derives the page name from the URL path
 * — both routes live under `ui/:uid/totp`, so both hydrate through the same arm and the mode has to
 * travel in the props either way.
 *
 * Belongs to the antd shell family (wiki: interaction-page-families): it carries a form the user works
 * in. That imposes the hydration contract — the server substitutes `<!--app-props-->` and the client
 * arm spreads those props — and violating either half erases the server-rendered content in a browser
 * only, with nothing logged.
 */

export interface TotpPageProps {
	uid: string;
	mode: 'verify' | 'enroll';
	errorMessage?: string;
	/* Enrol mode only. The QR's value; carries the secret. */
	otpauthUri?: string;
	/* Enrol mode only. The same secret as text, grouped in fours. */
	secretText?: string;
	/* The logo's versioned address, from the server: see LoginPage. */
	logoSrc?: string;
	switcher?: SwitcherProps;
	/* Where this sign-in leads: see LoginPage. */
	face: SignInFace;
}

function ErrorBanner({ message }: { message: string }) {
	return (
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
				<span style={{ color: foxVar('danger-text'), fontSize: '14px' }}>
					<ExclamationCircleOutlined aria-hidden="true" />
				</span>
				<span style={{ color: foxVar('danger-text'), fontSize: '14px' }}>
					{message}
				</span>
			</div>
		</Form.Item>
	);
}

export function TotpPage({
	uid,
	mode,
	errorMessage,
	otpauthUri,
	secretText,
	logoSrc = DEFAULT_LOGO,
	switcher,
	face
}: TotpPageProps) {
	const T = SIGN_IN_TEXTS[useLanguage()];
	const enrolling = mode === 'enroll';
	const action = buildUIPath(uid, enrolling ? 'totp/enroll' : 'totp');

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
				<SignInMasthead
					face={face}
					logoSrc={logoSrc}
					heading={enrolling ? T.totp.enrollHeading : T.totp.verifyHeading}
				/>
				<Typography.Paragraph
					type="secondary"
					style={{ fontSize: 13, marginTop: -12, marginBottom: 24 }}
				>
					{enrolling ? T.totp.enrollHint : T.totp.verifyHint}
				</Typography.Paragraph>

				{enrolling && otpauthUri && (
					<Flex
						vertical
						align="center"
						gap={12}
						style={{ marginBottom: 20 }}
					>
						{/*
						 * `type="svg"`, not the default canvas: a canvas renders empty on the server and is
						 * only drawn after hydration, so the QR would be missing for the whole first paint
						 * and entirely absent to anything that does not run scripts.
						 */}
						{/*
						 * Black on white in either scheme: a camera reads dark modules on a light field, and an
						 * inverted code — light on a dark page — is one many authenticator apps cannot scan.
						 */}
						<div
							style={{
								background: foxVar('qr-plate'),
								borderRadius: 8,
								lineHeight: 0
							}}
						>
							<QRCode
								type="svg"
								value={otpauthUri}
								size={180}
								color="#000000"
								bgColor="transparent"
							/>
						</div>
						{/*
						 * The real fallback, not a nicety. A camera that will not focus, an app with no
						 * scanner, a screen being read remotely — all of them come down to typing the secret,
						 * so it is shown in full rather than hidden behind a "can't scan?" toggle.
						 */}
						<Typography.Text
							type="secondary"
							style={{ fontSize: 12 }}
						>
							{T.totp.manualKey}
						</Typography.Text>
						<Typography.Text
							code
							copyable={{ text: secretText?.replace(/\s+/g, '') }}
							style={{ fontSize: 13, letterSpacing: 1 }}
						>
							{secretText}
						</Typography.Text>
					</Flex>
				)}

				<Form
					name="totp"
					method="post"
					action={action}
					onFinish={() => {
						document.forms.namedItem('totp')?.submit();
					}}
				>
					{errorMessage && <ErrorBanner message={errorMessage} />}
					<Form.Item
						name="code"
						rules={[{ required: true, message: T.totp.codeRequired }]}
					>
						<Input
							name="code"
							prefix={<SafetyCertificateOutlined aria-hidden="true" />}
							placeholder="000000"
							// A phone keypad rather than a full keyboard, and the browser's own one-time-code
							// autofill where the platform offers it.
							inputMode="numeric"
							autoComplete="one-time-code"
							autoFocus
							maxLength={8}
							style={{ letterSpacing: 4 }}
						/>
					</Form.Item>
					<Form.Item>
						<Button
							type="primary"
							htmlType="submit"
							block
						>
							{enrolling ? T.totp.confirm : T.totp.verify}
						</Button>
					</Form.Item>
				</Form>
				{switcher && <LanguageSwitch {...switcher} />}
			</Card>
		</Flex>
	);
}
