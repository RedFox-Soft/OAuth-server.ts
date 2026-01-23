import { renderToString } from 'react-dom/server';
import { StrictMode } from 'react';
import { LoginPage } from './loginPage.js';
import { ConsentPage } from './consentPage.js';
import { RegistrationPage } from './registration.js';

const htmlTeamplate = Bun.file('./lib/interactions/htmlTeamplate.html');

export async function loginServer(uid: string, errorMessage?: string) {
	let html = await htmlTeamplate.text();
	html = html
		.replace('<!--app-title-->', 'Login Page')
		.replace(
			'<!--app-props-->',
			`<script>window.PROPS=${JSON.stringify({ uid, errorMessage })}</script>`
		)
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
	return new Response(html, {
		status: errorMessage ? 400 : 200,
		headers: {
			'Content-Type': 'text/html; charset=utf-8'
		}
	});
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
	return new Response(html, {
		headers: {
			'Content-Type': 'text/html; charset=utf-8'
		}
	});
}

export async function consentServer(uid: string) {
	let html = await htmlTeamplate.text();
	html = html.replace('<!--app-title-->', 'Consent Page').replace(
		'<!--app-html-->',
		renderToString(
			<StrictMode>
				<ConsentPage
					uid={uid}
					clientName={''}
					scopes={[]}
				/>
			</StrictMode>
		)
	);
	return new Response(html, {
		headers: {
			'Content-Type': 'text/html; charset=utf-8'
		}
	});
}
