import React from 'react';
import { Result } from 'antd';
import { createCache, extractStyle, StyleProvider } from '@ant-design/cssinjs';
import { renderToStaticMarkup } from 'react-dom/server';

const cache = createCache();
function renderError(status: number, title: string, subTitle: string) {
	const html = renderToStaticMarkup(
		<StyleProvider cache={cache}>
			<Result
				status={status === 500 ? '500' : '403'}
				title={status.toString()}
				subTitle={subTitle}
			/>
		</StyleProvider>
	);
	const styleText = extractStyle(cache);

	return `<!DOCTYPE html>
	<html>
		<head>
			<meta charSet="utf-8" />
			<title>${title}</title>
			${styleText}
		</head>
		<body>${html}</body>
	</html>`;
}

export function getErrorHtmlResponse(
	status: number,
	error: string,
	message: string
) {
	const html = renderError(status, error, message);
	return new Response(html, {
		headers: {
			'Content-Type': 'text/html; charset=utf-8',
			'Cache-Control': 'no-store'
		}
	});
}
