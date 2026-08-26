import { ComponentProps } from 'react';
import { Result } from 'antd';
import { createCache, extractStyle, StyleProvider } from '@ant-design/cssinjs';
import { renderToStaticMarkup } from 'react-dom/server';
import { htmlResponse } from './csp.js';

type ResultStatus = ComponentProps<typeof Result>['status'];

/*
 * The illustration used to be `status === 500 ? '500' : '403'`, which drew a not-found — the most
 * common rendered error there is — as an access refusal, sending operators after a permissions
 * problem that did not exist. Anything without dedicated artwork gets the generic error icon rather
 * than borrowing artwork that names a cause which did not occur.
 */
function illustrationFor(status: number): ResultStatus {
	if (status === 404) {
		return '404';
	}
	if (status === 403) {
		return '403';
	}
	if (status >= 500) {
		return '500';
	}
	return 'error';
}

const cache = createCache();
function renderError(
	status: number,
	title: string,
	subTitle: string,
	reference?: string
) {
	/*
	 * The reference is rendered as plain text beside the message, and only when the fault was recorded.
	 * It is the whole point of showing a person an error page rather than a status code: they can quote
	 * it to an operator, who resolves it to the one record. It discloses nothing — the identifier is
	 * random and carries no state.
	 */
	const html = renderToStaticMarkup(
		<StyleProvider cache={cache}>
			<Result
				status={illustrationFor(status)}
				title={status.toString()}
				subTitle={
					reference ? `${subTitle} (reference: ${reference})` : subTitle
				}
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
	message: string,
	reference?: string
) {
	const html = renderError(status, error, message, reference);
	// Without an explicit status the Response defaults to 200, so an HTML-preferring caller was told
	// "OK" for every error the server rendered as a page — including a not-found.
	return htmlResponse(html, { status });
}
