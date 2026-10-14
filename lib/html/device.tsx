import type { ReactNode } from 'react';
import { Button, Card, Flex, Typography } from 'antd';

import {
	input as inputForm,
	confirm as confirmForm
} from '../helpers/user_code_form.ts';
import { htmlResponse } from './csp.js';
import { esc } from './escape.js';
import { isRecord } from '../helpers/_/object.ts';
import type { Language } from '../i18n/languages.js';
import { Message } from '../i18n/message.js';
import { PAGES_TEXTS } from '../i18n/texts/pages/index.js';
import { foxVar } from './theme/palette.js';
import { renderEndUserTree } from './theme/dark.js';

const { Title, Paragraph, Text } = Typography;

// Renders an antd component tree to a self-contained HTML document. antd's cssinjs styles are
// extracted inline (no external stylesheet / web font); a small `.red` rule preserves the exact
// `<p class="red">` error markup embedded below, in the palette's error colour for either scheme.
function renderPage(title: string, node: ReactNode, language: Language) {
	const page = renderEndUserTree(<>{node}</>, { language });

	const html = `<!DOCTYPE html>
<html lang="${language}">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(title)}</title>
  ${page.head}
  <style>.red{color:${foxVar('danger-text')}}</style>
</head>
<body>${page.html}</body>
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
				padding: '0 16px',
				boxSizing: 'border-box',
				alignItems: 'center',
				backgroundColor: foxVar('page')
			}}
		>
			<Card
				style={{
					width: '100%',
					maxWidth: 400,
					padding: 24,
					borderRadius: 12,
					boxShadow: `0 2px 8px ${foxVar('shadow')}`
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
	err,
	language = 'en'
}: {
	action: string;
	secret: string;
	charset?: string;
	// Whatever the handler caught: a re-render names the code it failed on, a protocol error its status.
	err?: unknown;
	language?: Language;
}) {
	const t = PAGES_TEXTS[language].device;
	const failure = isRecord(err) ? err : {};
	let message: ReactNode;
	if (err && (failure.userCode || failure.name === 'NoCodeError')) {
		message = <p className="red">{t.errors.incorrectCode}</p>;
	} else if (err && failure.name === 'AbortedError') {
		message = <p className="red">{t.errors.aborted}</p>;
	} else if (err && failure.name === 'UnfinishedError') {
		message = <p className="red">{t.errors.unfinished}</p>;
	} else if (err) {
		message = <p className="red">{t.errors.failed}</p>;
	} else {
		message = <Paragraph>{t.input.prompt}</Paragraph>;
	}

	const form = inputForm(action, secret, undefined, charset, language);

	const html = renderPage(
		t.input.title,
		<CenteredCard>
			<Title
				level={1}
				style={{ textAlign: 'center' }}
			>
				{t.input.heading}
			</Title>
			{message}
			<div dangerouslySetInnerHTML={{ __html: form }} />
			<Button
				block
				type="primary"
				htmlType="submit"
				form="op.deviceInputForm"
			>
				{t.input.continue}
			</Button>
		</CenteredCard>,
		language
	);

	const status = typeof failure.status === 'number' ? failure.status : 400;
	return htmlResponse(html, { status: err ? status : 200, language });
}

export function deviceConfirmPage({
	action,
	secret,
	userCode,
	client,
	language = 'en'
}: {
	action: string;
	secret: string;
	userCode: string;
	client: { clientId: string; clientName?: string };
	language?: Language;
}) {
	const t = PAGES_TEXTS[language].device.confirm;
	const { clientId, clientName } = client;
	const form = confirmForm(action, secret, userCode);

	const html = renderPage(
		t.title,
		<CenteredCard>
			<Title
				level={1}
				style={{ textAlign: 'center' }}
			>
				{t.heading}
			</Title>
			<Paragraph style={{ textAlign: 'center' }}>
				<Text strong>{clientName || clientId}</Text>
				<br />
				<br />
				{t.codeIntro}
				<br />
				<br />
				<Text code>
					<span dir="ltr">{userCode}</span>
				</Text>
				<br />
				<br />
				<Text type="secondary">{t.warning}</Text>
			</Paragraph>
			<div dangerouslySetInnerHTML={{ __html: form }} />
			<Button
				block
				type="primary"
				htmlType="submit"
				form="op.deviceConfirmForm"
			>
				{t.continue}
			</Button>
			<Flex justify="center">
				<Button
					type="link"
					htmlType="submit"
					form="op.deviceConfirmForm"
					name="abort"
					value="yes"
				>
					{t.abort}
				</Button>
			</Flex>
		</CenteredCard>,
		language
	);

	return htmlResponse(html, { language });
}

export function deviceSuccessPage({
	client,
	language = 'en'
}: {
	client: { clientName?: string };
	language?: Language;
}) {
	const t = PAGES_TEXTS[language].device.success;
	const { clientName } = client;

	const html = renderPage(
		t.title,
		<CenteredCard>
			<Title
				level={1}
				style={{ textAlign: 'center' }}
			>
				{t.heading}
			</Title>
			<Paragraph style={{ textAlign: 'center' }}>
				{clientName ? (
					<Message
						t={t.messageWithApp}
						values={{ app: clientName }}
					/>
				) : (
					t.message
				)}
			</Paragraph>
		</CenteredCard>,
		language
	);

	return htmlResponse(html, { language });
}
