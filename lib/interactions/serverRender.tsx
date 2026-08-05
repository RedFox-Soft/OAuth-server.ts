import { renderToString } from 'react-dom/server';
import { StrictMode } from 'react';
import { LoginPage } from './loginPage.js';
import { ConsentPage } from './consentPage.js';
import { RegistrationPage } from './registration.js';
import type { ConsentView } from './consentView.js';
import { htmlResponse } from '../html/csp.js';
import { versionedAsset } from '../html/versionedAsset.js';
import { ZeroRuntime } from '../html/zeroRuntime.js';

const htmlTeamplate = Bun.file('./lib/interactions/htmlTeamplate.html');

// escape `<` so a client name / scope value can't break out of the script tag
function propsScript(props: unknown): string {
	return `<script>window.PROPS=${JSON.stringify(props).replace(/</g, '\\u003c')}</script>`;
}

/*
 * reset before components, so antd's reset does not override component styles.
 */
function styleLinks(): string {
	return [
		`<link rel="stylesheet" href="${versionedAsset('reset.css')}" />`,
		`<link rel="stylesheet" href="${versionedAsset('antd.css')}" />`
	].join('');
}

export async function loginServer(
	uid: string,
	options: { errorMessage?: string; notice?: string } = {}
) {
	const { errorMessage } = options;
	// Exclusivity is a property of this function rather than a promise made at each call site: a rejected
	// submission must never be accompanied by the notice the page was reached with.
	const notice = errorMessage ? undefined : options.notice;

	let html = await htmlTeamplate.text();
	html = html
		.replace('/public/loginClient.js', versionedAsset('loginClient.js'))
		.replace('/public/favicon.ico', versionedAsset('favicon.ico'))
		.replace('<!--app-title-->', 'Login Page')
		.replace('<!--app-styles-->', styleLinks())
		.replace('<!--app-props-->', propsScript({ uid, errorMessage, notice }))
		.replace(
			'<!--app-html-->',
			renderToString(
				<StrictMode>
					<ZeroRuntime>
						<LoginPage
							uid={uid}
							errorMessage={errorMessage}
							notice={notice}
						/>
					</ZeroRuntime>
				</StrictMode>
			)
		);
	// A notice is not a failure: only the error re-render answers 400.
	return htmlResponse(html, { status: errorMessage ? 400 : 200 });
}

export async function registrationServer(
	uid: string,
	options: { errorMessage?: string; email?: string } = {}
) {
	const { errorMessage, email } = options;

	let html = await htmlTeamplate.text();
	html = html
		.replace('/public/loginClient.js', versionedAsset('loginClient.js'))
		.replace('/public/favicon.ico', versionedAsset('favicon.ico'))
		.replace('<!--app-title-->', 'Registration Page')
		.replace('<!--app-styles-->', styleLinks())
		// The props are what the hydrated tree is built from: without them React replaces the
		// server-rendered page with one that never heard about the error, silently and in the browser
		// only.
		.replace('<!--app-props-->', propsScript({ uid, errorMessage, email }))
		.replace(
			'<!--app-html-->',
			renderToString(
				<StrictMode>
					<ZeroRuntime>
						<RegistrationPage
							uid={uid}
							errorMessage={errorMessage}
							email={email}
						/>
					</ZeroRuntime>
				</StrictMode>
			)
		);
	// Neither submitted password reaches this document — not the markup, not the props (spec FR-011).
	return htmlResponse(html, { status: errorMessage ? 400 : 200 });
}

export async function consentServer(view: ConsentView) {
	let html = await htmlTeamplate.text();
	html = html
		.replace('/public/loginClient.js', versionedAsset('loginClient.js'))
		.replace('/public/favicon.ico', versionedAsset('favicon.ico'))
		.replace('<!--app-title-->', 'Consent Page')
		.replace('<!--app-styles-->', styleLinks())
		.replace('<!--app-props-->', propsScript(view))
		.replace(
			'<!--app-html-->',
			renderToString(
				<StrictMode>
					<ZeroRuntime>
						<ConsentPage {...view} />
					</ZeroRuntime>
				</StrictMode>
			)
		);
	return htmlResponse(html);
}
