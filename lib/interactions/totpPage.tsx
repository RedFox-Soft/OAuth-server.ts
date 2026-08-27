import {
	ExclamationCircleOutlined,
	SafetyCertificateOutlined
} from '@ant-design/icons';
import { Button, Card, Flex, Form, Input, QRCode, Typography } from 'antd';
import { buildUIPath } from './buildUIPath.js';
import { versionedAsset } from '../html/versionedAsset.js';

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
}

function ErrorBanner({ message }: { message: string }) {
	return (
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
				<span style={{ color: '#ff4d4f', fontSize: '14px' }}>{message}</span>
			</div>
		</Form.Item>
	);
}

export function TotpPage({
	uid,
	mode,
	errorMessage,
	otpauthUri,
	secretText
}: TotpPageProps) {
	const enrolling = mode === 'enroll';
	const action = buildUIPath(uid, enrolling ? 'totp/enroll' : 'totp');

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
					<h2>
						{enrolling ? 'Set up your authenticator' : 'Two-step verification'}
					</h2>
					<Typography.Text
						type="secondary"
						style={{ fontSize: 13 }}
					>
						{enrolling
							? 'Scan this with an authenticator app, then enter the code it shows.'
							: 'Enter the current code from your authenticator app.'}
					</Typography.Text>
				</div>

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
						<QRCode
							type="svg"
							value={otpauthUri}
							size={180}
						/>
						{/*
						 * The real fallback, not a nicety. A camera that will not focus, an app with no
						 * scanner, a screen being read remotely — all of them come down to typing the secret,
						 * so it is shown in full rather than hidden behind a "can't scan?" toggle.
						 */}
						<Typography.Text
							type="secondary"
							style={{ fontSize: 12 }}
						>
							Or enter this key manually:
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
						rules={[{ required: true, message: 'Please enter your code!' }]}
					>
						<Input
							name="code"
							prefix={<SafetyCertificateOutlined />}
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
							{enrolling ? 'Confirm' : 'Verify'}
						</Button>
					</Form.Item>
				</Form>
			</Card>
		</Flex>
	);
}
