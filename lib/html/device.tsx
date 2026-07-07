import type { ReactNode } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { createCache, extractStyle, StyleProvider } from '@ant-design/cssinjs';
import { Button, Card, Flex, Typography } from 'antd';

import {
	input as inputForm,
	confirm as confirmForm
} from '../helpers/user_code_form.ts';

const { Title, Paragraph, Text } = Typography;

const htmlHeaders = { 'Content-Type': 'text/html; charset=utf-8' };

// Renders an antd component tree to a self-contained HTML document. antd's cssinjs styles are
// extracted inline (no external stylesheet / web font); a small `.red` rule preserves the exact
// `<p class="red">` error markup embedded below.
function renderPage(title: string, node: ReactNode) {
	const cache = createCache();
	const body = renderToStaticMarkup(
		<StyleProvider cache={cache}>{node}</StyleProvider>
	);
	const styleText = extractStyle(cache);

	const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${title}</title>
  <style>${styleText}</style>
  <style>.red{color:#d50000}</style>
</head>
<body>${body}</body>
</html>`;

	return html;
}

function CenteredCard({ children }: { children: ReactNode }) {
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
				{children}
			</Card>
		</Flex>
	);
}

// Default device-flow interaction pages, rendered with antd through the html layer (no
// per-instance override seam, no external fonts). The error argument, when present, re-renders the
// input page with the message that matches the failure; ReRenderErrors (bad/missing/expired/used
// code) carry status 200, request/client errors carry status 400.
export function deviceInputPage({
	action,
	secret,
	charset,
	err
}: {
	action: string;
	secret: string;
	charset?: string;
	err?: { status?: number; userCode?: string; name?: string };
}) {
	let message: ReactNode;
	if (err && (err.userCode || err.name === 'NoCodeError')) {
		message = (
			<p className="red">The code you entered is incorrect. Try again</p>
		);
	} else if (err && err.name === 'AbortedError') {
		message = <p className="red">The Sign-in request was interrupted</p>;
	} else if (err) {
		message = <p className="red">There was an error processing your request</p>;
	} else {
		message = <Paragraph>Enter the code displayed on your device</Paragraph>;
	}

	const form = inputForm(action, secret, undefined, charset);

	const html = renderPage(
		'Sign-in',
		<CenteredCard>
			<Title
				level={1}
				style={{ textAlign: 'center' }}
			>
				Sign-in
			</Title>
			{message}
			<div dangerouslySetInnerHTML={{ __html: form }} />
			<Button
				block
				type="primary"
				htmlType="submit"
				form="op.deviceInputForm"
			>
				Continue
			</Button>
		</CenteredCard>
	);

	return new Response(html, {
		status: err ? (err.status ?? 400) : 200,
		headers: htmlHeaders
	});
}

export function deviceConfirmPage({
	action,
	secret,
	userCode,
	client
}: {
	action: string;
	secret: string;
	userCode: string;
	client: { clientId: string; clientName?: string };
}) {
	const { clientId, clientName } = client;
	const form = confirmForm(action, secret, userCode);

	const html = renderPage(
		'Device Login Confirmation',
		<CenteredCard>
			<Title
				level={1}
				style={{ textAlign: 'center' }}
			>
				Confirm Device
			</Title>
			<Paragraph style={{ textAlign: 'center' }}>
				<Text strong>{clientName || clientId}</Text>
				<br />
				<br />
				The following code should be displayed on your device
				<br />
				<br />
				<Text code>{userCode}</Text>
				<br />
				<br />
				<Text type="secondary">
					If you did not initiate this action, the code does not match or are
					unaware of such device in your possession please close this window or
					click abort.
				</Text>
			</Paragraph>
			<div dangerouslySetInnerHTML={{ __html: form }} />
			<Button
				block
				type="primary"
				htmlType="submit"
				form="op.deviceConfirmForm"
			>
				Continue
			</Button>
			<Flex justify="center">
				<Button
					type="link"
					htmlType="submit"
					form="op.deviceConfirmForm"
					name="abort"
					value="yes"
				>
					[ Abort ]
				</Button>
			</Flex>
		</CenteredCard>
	);

	return new Response(html, { headers: htmlHeaders });
}

export function deviceSuccessPage({
	client
}: {
	client: { clientName?: string };
}) {
	const { clientName } = client;

	const html = renderPage(
		'Sign-in Success',
		<CenteredCard>
			<Title
				level={1}
				style={{ textAlign: 'center' }}
			>
				Sign-in Success
			</Title>
			<Paragraph style={{ textAlign: 'center' }}>
				Your sign-in {clientName ? `with ${clientName}` : ''} was successful,
				you can now close this page.
			</Paragraph>
		</CenteredCard>
	);

	return new Response(html, { headers: htmlHeaders });
}
