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

export async function loginServer(uid: string, errorMessage?: string) {
	let html = await htmlTeamplate.text();
	html = html
		.replace('<!--app-title-->', 'Login Page')
		.replace('<!--app-props-->', propsScript({ uid, errorMessage }))
		.replace(
			'<!--app-html-->',
			renderToString(
				<StrictMode>
					<LoginPage
						uid={uid}
						errorMessage={errorMessage}
					/>
				</StrictMode>
			)
		);
	return htmlResponse(html, { status: errorMessage ? 400 : 200 });
}

export async function registrationServer(uid: string) {
	let html = await htmlTeamplate.text();
	html = html.replace('<!--app-title-->', 'Registration Page').replace(
		'<!--app-html-->',
		renderToString(
			<StrictMode>
				<RegistrationPage uid={uid} />
			</StrictMode>
		)
	);
	// No props script yet — the registration page's hydration props are backlog task 17's work. The
	// policy is derived from the document, so adding one needs no change here.
	return htmlResponse(html);
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
