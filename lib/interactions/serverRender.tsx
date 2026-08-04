import { renderToString } from 'react-dom/server';
import { StrictMode } from 'react';
import { LoginPage } from './loginPage.js';
import { ConsentPage } from './consentPage.js';
import { RegistrationPage } from './registration.js';
import type { ConsentView } from './consentView.js';
import { htmlResponse } from '../html/csp.js';

const htmlTeamplate = Bun.file('./lib/interactions/htmlTeamplate.html');

// escape `<` so a client name / scope value can't break out of the script tag
function propsScript(props: unknown): string {
	return `<script>window.PROPS=${JSON.stringify(props).replace(/</g, '\\u003c')}</script>`;
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
		.replace('<!--app-title-->', 'Login Page')
		.replace('<!--app-props-->', propsScript({ uid, errorMessage, notice }))
		.replace(
			'<!--app-html-->',
			renderToString(
				<StrictMode>
					<LoginPage
						uid={uid}
						errorMessage={errorMessage}
						notice={notice}
					/>
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
		.replace('<!--app-title-->', 'Registration Page')
		// The props are what the hydrated tree is built from: without them React replaces the
		// server-rendered page with one that never heard about the error, silently and in the browser
		// only.
		.replace('<!--app-props-->', propsScript({ uid, errorMessage, email }))
		.replace(
			'<!--app-html-->',
			renderToString(
				<StrictMode>
					<RegistrationPage
						uid={uid}
						errorMessage={errorMessage}
						email={email}
					/>
				</StrictMode>
			)
		);
	// Neither submitted password reaches this document — not the markup, not the props (spec FR-011).
	return htmlResponse(html, { status: errorMessage ? 400 : 200 });
}

export async function consentServer(view: ConsentView) {
	let html = await htmlTeamplate.text();
	html = html
		.replace('<!--app-title-->', 'Consent Page')
		.replace('<!--app-props-->', propsScript(view))
		.replace(
			'<!--app-html-->',
			renderToString(
				<StrictMode>
					<ConsentPage {...view} />
				</StrictMode>
			)
		);
	return htmlResponse(html);
}
