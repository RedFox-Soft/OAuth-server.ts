// An administrator said a sign-in to their console account was not theirs (specs/138): every other super
// administrator is told, in English like the console's other notices to its administrators. Who, when and from where
// in words; never the network address, which stays behind the audited Sign-ins page.

import { esc } from '../../html/escape.js';

export interface SignInReportedFacts {
	administrator: string;
	at: Date;
	app: string;
	browser: string | null;
	place: string | null;
	network: string | null;
	consoleUrl: string;
}

export function signInReportedEmail(facts: SignInReportedFacts): {
	subject: string;
	html: string;
	text: string;
} {
	const when = `${facts.at.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
	const lines = [
		`When: ${when}`,
		`Signed in to: ${facts.app}`,
		...(facts.browser === null ? [] : [`Browser: ${facts.browser}`]),
		...(facts.place === null ? [] : [`Place: ${facts.place}`]),
		...(facts.network === null ? [] : [`Network: ${facts.network}`])
	];
	const what = `${facts.administrator} said this sign-in to their console account was not theirs:`;
	const done =
		'Their console sessions and tokens have ended. Set them a new password, or reset their authenticator, under Administrators, Accounts, and read their sign-ins there.';
	return {
		subject: `${facts.administrator} reported a sign-in that wasn't theirs`,
		html: [
			`<div style="font-family: Arial, Helvetica, sans-serif; max-width: 480px; margin: 0 auto; color: #1f1f1f;">`,
			`<p>${esc(what)}</p>`,
			`<p>${lines.map((line) => esc(line)).join('<br/>')}</p>`,
			`<p>${esc(done)}</p>`,
			`<p><a href="${esc(facts.consoleUrl)}">${esc(facts.consoleUrl)}</a></p>`,
			`</div>`
		].join(''),
		text: [what, '', ...lines, '', done, facts.consoleUrl].join('\n')
	};
}
